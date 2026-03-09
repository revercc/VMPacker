package elf

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"path/filepath"

	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/vmpacker/pkg/arch/arm64"
	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ELF 解析器 + 修改器 v3
//
// 注入策略: PT_NOTE → PT_LOAD 劫持
//   1. 将 VM 解释器 blob + 加密字节码追加到文件末尾
//   2. 将 PT_NOTE 段转换为 PT_LOAD (RX)，映射追加的数据
//   3. 新 LOAD 段使用独立的虚拟地址 (0x800000 起)
//   4. 原函数改写为跳板 → BL 到新段中的 VM 解释器
//
// 优点: 不移动任何现有数据，不破坏段对齐
// ============================================================

// AddrSpec 按地址指定函数
type AddrSpec struct {
	Addr uint64
	End  uint64 // 0 = 自动检测
	Name string // 可选名称
}

// 收集所有需要运行时重定位信息
type RuntimeReloc struct {
	WritePos uint64 // 相对于 bc 的偏移（待重定位数据的地址在最终字节码中的偏移）
	Offset   uint64 // 相对偏移 （需要加上运行时基地址，完成重定位
	FuncId   uint64 // 标记此重定位信息属于哪个函数的（函数id
}

// ParseAddrSpec 解析地址规格: "0xADDR", "0xSTART-0xEND", "0xSTART-0xEND:name"
func ParseAddrSpec(s string) (AddrSpec, error) {
	var spec AddrSpec
	// 分离可选名称 (最后一个冒号后面)
	if idx := strings.LastIndex(s, ":"); idx > 2 {
		candidate := s[idx+1:]
		// 如果不像十六进制数则是名称
		if _, err := strconv.ParseUint(candidate, 0, 64); err != nil {
			spec.Name = candidate
			s = s[:idx]
		}
	}
	// 解析地址范围
	if parts := strings.Split(s, "-"); len(parts) == 2 {
		start, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			return spec, fmt.Errorf("起始地址无效: %s", parts[0])
		}
		end, err := strconv.ParseUint(parts[1], 0, 64)
		if err != nil {
			return spec, fmt.Errorf("结束地址无效: %s", parts[1])
		}
		if end <= start {
			return spec, fmt.Errorf("结束地址必须大于起始地址")
		}
		spec.Addr = start
		spec.End = end
	} else {
		addr, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return spec, fmt.Errorf("地址无效: %s", s)
		}
		spec.Addr = addr
	}
	if spec.Name == "" {
		spec.Name = fmt.Sprintf("sub_%X", spec.Addr)
	}
	return spec, nil
}

// Packer ELF VMP 打包器
type Packer struct {
	inputPath    string
	outputPath   string
	soName       string
	funcNames    []string
	addrSpecs    []AddrSpec
	verbose      bool
	stripSymbols bool
	debug        bool
	tokenEntry   bool // Token 化入口模式
	data         []byte
	interpBlob   []byte
	relocations  []arm64.Relocation // 收集所有重定位
}

// FuncBytecode 保存单个函数的加密字节码和元信息
type FuncBytecode struct {
	FI               *vm.FuncInfo
	Encrypted        []byte
	XorKey           byte
	reverseOffsetMap map[int]int // 反转后 offset 映射 (原 offset → 新 offset)
}

// NewPacker 创建 ELF 打包器
func NewPacker(input, output string, funcs []string, addrSpecs []AddrSpec, verbose, strip, debug, tokenEntry bool, interpBlob []byte) *Packer {
	return &Packer{
		inputPath:    input,
		outputPath:   output,
		funcNames:    funcs,
		addrSpecs:    addrSpecs,
		verbose:      verbose,
		stripSymbols: strip,
		debug:        debug,
		tokenEntry:   tokenEntry,
		interpBlob:   interpBlob,
	}
}

// FindFunction 在 ELF 中查找函数
func (p *Packer) FindFunction(f *elf.File, name string) (*vm.FuncInfo, error) {
	syms, err := f.Symbols()
	if err != nil {
		syms, err = f.DynamicSymbols()
	}
	if err != nil {
		return nil, fmt.Errorf("reading symbol table failed: %v", err)
	}
	for _, sym := range syms {
		if sym.Name == name && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
			info := &vm.FuncInfo{
				Name: sym.Name,
				Addr: sym.Value,
				Size: sym.Size,
			}
			if int(sym.Section) < len(f.Sections) {
				sec := f.Sections[sym.Section]
				info.Section = sec.Name
				info.Offset = sec.Offset + (sym.Value - sec.Addr)
			}
			return info, nil
		}
	}
	return nil, fmt.Errorf("function '%s' not found", name)
}

// FindFunctionByAddr 通过地址查找函数
func (p *Packer) FindFunctionByAddr(f *elf.File, spec AddrSpec) (*vm.FuncInfo, error) {
	// 优先在 .text 段中定位
	textSec := f.Section(".text")

	var secName string
	var secAddr, secOffset, secSize uint64
	var secData []byte

	if textSec != nil {
		secName = ".text"
		secAddr = textSec.Addr
		secOffset = textSec.Offset
		secSize = textSec.Size
		d, err := textSec.Data()
		if err != nil {
			return nil, fmt.Errorf("reading .text failed: %v", err)
		}
		secData = d
	} else {
		// Fallback: 在可执行 LOAD segment 中查找
		found := false
		for _, prog := range f.Progs {
			if prog.Type != elf.PT_LOAD {
				continue
			}
			if prog.Flags&elf.PF_X == 0 {
				continue
			}
			segEnd := prog.Vaddr + prog.Memsz
			if spec.Addr >= prog.Vaddr && spec.Addr < segEnd {
				secName = "__LOAD_X"
				secAddr = prog.Vaddr
				secOffset = prog.Off
				secSize = prog.Filesz
				d := make([]byte, prog.Filesz)
				if _, err := prog.ReadAt(d, 0); err != nil {
					return nil, fmt.Errorf("reading LOAD segment failed: %v", err)
				}
				secData = d
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("address 0x%X not in any executable segment", spec.Addr)
		}
	}

	// 确认地址在范围内
	if spec.Addr < secAddr || spec.Addr >= secAddr+secSize {
		return nil, fmt.Errorf("address 0x%X not in %s (0x%X-0x%X)",
			spec.Addr, secName, secAddr, secAddr+secSize)
	}

	var size uint64
	if spec.End > 0 {
		// 用户指定了结束地址
		size = spec.End - spec.Addr
	} else {
		// 自动检测: 扫描到 RET (0xD65F03C0) 指令
		startOff := spec.Addr - secAddr
		found := false
		for i := startOff; i+4 <= uint64(len(secData)); i += 4 {
			inst := binary.LittleEndian.Uint32(secData[i:])
			if inst == 0xD65F03C0 { // RET
				size = i + 4 - startOff
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("cannot detect function size at 0x%X (no RET found)", spec.Addr)
		}
	}

	fi := &vm.FuncInfo{
		Name:    spec.Name,
		Addr:    spec.Addr,
		Size:    size,
		Section: secName,
		Offset:  secOffset + (spec.Addr - secAddr),
	}
	return fi, nil
}

// ExtractFuncCode 提取函数机器码
func (p *Packer) ExtractFuncCode(f *elf.File, fi *vm.FuncInfo) ([]byte, error) {
	if fi.Size == 0 {
		return nil, fmt.Errorf("function %s has zero size", fi.Name)
	}

	if fi.Section == "__LOAD_X" {
		// 无 section headers: 从 LOAD segment 读取
		for _, prog := range f.Progs {
			if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
				continue
			}
			segEnd := prog.Vaddr + prog.Filesz
			if fi.Addr >= prog.Vaddr && fi.Addr+fi.Size <= segEnd {
				localOff := fi.Addr - prog.Vaddr
				code := make([]byte, fi.Size)
				if _, err := prog.ReadAt(code, int64(localOff)); err != nil {
					return nil, fmt.Errorf("reading LOAD segment failed: %v", err)
				}
				return code, nil
			}
		}
		return nil, fmt.Errorf("function %s (0x%X) not in any LOAD segment", fi.Name, fi.Addr)
	}

	section := f.Section(fi.Section)
	if section == nil {
		return nil, fmt.Errorf("section %s not found", fi.Section)
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("reading section data failed: %v", err)
	}
	localOff := fi.Addr - section.Addr
	if localOff+fi.Size > uint64(len(data)) {
		return nil, fmt.Errorf("function exceeds section bounds")
	}
	code := make([]byte, fi.Size)
	copy(code, data[localOff:localOff+fi.Size])
	return code, nil
}

// DecodeFunction 解码 ARM64 指令
func (p *Packer) DecodeFunction(code []byte) []vm.Instruction {
	dec := arm64.NewDecoder()
	var insts []vm.Instruction
	for off := 0; off+4 <= len(code); off += 4 {
		raw := binary.LittleEndian.Uint32(code[off:])
		inst := dec.Decode(raw, off)
		insts = append(insts, inst)
	}
	return insts
}

// Process 主入口
func (p *Packer) Process() error {
	var err error
	p.data, err = os.ReadFile(p.inputPath)
	if err != nil {
		return fmt.Errorf("reading file failed: %v", err)
	}

	f, err := elf.NewFile(bytes.NewReader(p.data))
	if err != nil {
		return fmt.Errorf("parsing ELF failed: %v", err)
	}
	defer f.Close()

	if f.Machine != elf.EM_AARCH64 {
		return fmt.Errorf("ARM64 only, got: %s", f.Machine)
	}
	if f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("64-bit ELF only")
	}

	// 获取 so name
	p.soName = filepath.Base(p.inputPath)

	fmt.Printf("[*] ELF: %s, Type: %s, Name: %s\n", f.Machine, f.Type, p.soName)
	fmt.Printf("[*] VM interp blob: %d bytes\n", len(p.interpBlob))

	dec := arm64.NewDecoder()

	// 第一阶段: 收集所有函数的字节码
	type funcEntry struct {
		name   string
		finder func() (*vm.FuncInfo, error)
	}
	var entries []funcEntry
	for _, funcName := range p.funcNames {
		fn := funcName
		entries = append(entries, funcEntry{fn, func() (*vm.FuncInfo, error) {
			return p.FindFunction(f, fn)
		}})
	}
	for _, spec := range p.addrSpecs {
		s := spec
		entries = append(entries, funcEntry{s.Name, func() (*vm.FuncInfo, error) {
			return p.FindFunctionByAddr(f, s)
		}})
	}

	var funcs []FuncBytecode
	for _, entry := range entries {
		fmt.Printf("\n[*] Processing: %s\n", entry.name)

		fi, err := entry.finder()
		if err != nil {
			return err
		}
		fmt.Printf("    Addr: 0x%X, Size: %d bytes, Section: %s\n",
			fi.Addr, fi.Size, fi.Section)

		code, err := p.ExtractFuncCode(f, fi)
		if err != nil {
			return err
		}

		insts := p.DecodeFunction(code)
		fmt.Printf("    Instructions: %d\n", len(insts))

		if p.verbose {
			fmt.Println("    --- Disasm ---")
			for _, inst := range insts {
				fmt.Printf("    0x%04X: %-12s raw=0x%08X\n",
					inst.Offset, dec.InstName(inst.Op), inst.Raw)
			}
			fmt.Println("    --- End ---")
		}

		trans := arm64.NewTranslator(fi.Addr, int(fi.Size), fi.Name)
		if p.debug {
			trans.SetDebug(true)
		}
		result, err := trans.Translate(insts)
		if err != nil {
			return fmt.Errorf("translation failed: %v", err)
		}

		fmt.Printf("    Translated: %d/%d\n", result.TransInsts, result.TotalInsts)
		fmt.Printf("    Bytecode: %d bytes\n", len(result.Bytecode))

		if len(result.Unsupported) > 0 {
			fmt.Printf("    [!] Unsupported (%d):\n", len(result.Unsupported))
			for _, u := range result.Unsupported {
				fmt.Printf("        %s\n", u)
			}

			// 生成翻译失败 debug 文件
			debugPath := p.outputPath + ".debug.txt"
			df, derr := os.Create(debugPath)
			if derr != nil {
				fmt.Printf("    [!] debug 文件创建失败: %v\n", derr)
			} else {
				fmt.Fprintf(df, "================================================================\n")
				fmt.Fprintf(df, "翻译失败报告 — %s @ 0x%X\n", entry.name, fi.Addr)
				fmt.Fprintf(df, "函数大小: %d bytes, 总指令数: %d, 已翻译: %d\n",
					fi.Size, result.TotalInsts, result.TransInsts)
				fmt.Fprintf(df, "================================================================\n\n")
				fmt.Fprintf(df, "不支持的指令 (%d):\n\n", len(result.Unsupported))

				// 构建 offset→Instruction 索引，用于提取原始字节
				instMap := make(map[int]vm.Instruction)
				for _, inst := range insts {
					instMap[inst.Offset] = inst
				}

				for idx, u := range result.Unsupported {
					fmt.Fprintf(df, "[%d] %s\n", idx+1, u)

					// 尝试从 unsupported 字符串解析偏移 (格式: "偏移 0xNNNN: ...")
					var off int
					if _, err := fmt.Sscanf(u, "偏移 0x%X:", &off); err == nil {
						if inst, ok := instMap[off]; ok {
							raw := inst.Raw
							fmt.Fprintf(df, "    原始字节: %02X %02X %02X %02X\n",
								byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24))
							fmt.Fprintf(df, "    绝对地址: 0x%X\n", fi.Addr+uint64(off))
						}
					}
					fmt.Fprintln(df)
				}

				fmt.Fprintf(df, "================================================================\n")
				fmt.Fprintf(df, "修复建议:\n")
				fmt.Fprintf(df, "- 为每条不支持的指令编写 demo 测试用例 (参考 demo/ 目录)\n")
				fmt.Fprintf(df, "- 在 pkg/arch/arm64/translator.go translateOne() 中添加对应 case\n")
				fmt.Fprintf(df, "- 使用 -v 标志查看完整反汇编上下文\n")
				fmt.Fprintf(df, "================================================================\n")

				df.Close()
				fmt.Printf("    [+] 翻译失败 debug 文件: %s\n", debugPath)
			}

			return fmt.Errorf("translation aborted: %d unsupported instruction(s) in %s — cannot produce safe output",
				len(result.Unsupported), entry.name)
		}

		// debug: 生成对照文件 (必须在反转/加密之前, 使用原始正向字节码)
		if p.debug {
			debugPath := p.outputPath + ".debug.txt"
			df, derr := os.OpenFile(debugPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if derr != nil {
				fmt.Printf("    [!] debug file create failed: %v\n", derr)
			} else {
				fmt.Fprintf(df, "================================================================\n")
				fmt.Fprintf(df, "Function: %s @ 0x%X (size: %d)\n", entry.name, fi.Addr, fi.Size)
				fmt.Fprintf(df, "VM bytecode: %d bytes (pre-reverse)\n", len(result.Bytecode))
				fmt.Fprintf(df, "================================================================\n\n")

				for _, dbg := range trans.DebugLog() {
					vmLines := vm.DisasmRange(result.Bytecode, dbg.VMStart, dbg.VMEnd)
					fmt.Fprintf(df, "ARM64  %04X: %-16s  (raw=0x%08X)\n",
						dbg.ARM64Offset, dbg.ARM64Asm, dbg.ARM64Raw)
					for _, vl := range vmLines {
						fmt.Fprintf(df, "  VM   %s\n", vl)
					}
					fmt.Fprintln(df)
				}

				df.Close()
				fmt.Printf("    [+] Debug: %s\n", debugPath)
			}
		}

		// 收集重定位信息
		if len(result.Relocations) > 0 {
			p.relocations = append(p.relocations, result.Relocations...)
		}

		// ---- PC 反向遍历: 反转指令顺序 ----
		// 必须在 OpcodeCryptor 之前执行 (加密使用最终 pc 位置)
		reversed, offsetMap := reverseInstructions(result.Bytecode, result.CodeLen)

		// 重映射分支目标 (使用反转后的偏移)
		newCodeLen := len(reversed)
		remapBranchTargets(reversed, newCodeLen, offsetMap, p.verbose)

		// 重映射 addr_map 中的 vm_off (BR 间接跳转)
		// trailer 在 result.Bytecode[result.CodeLen:] 中，每个 entry 8B: [arm64_off:u32][vm_off:u32]
		mapCount := binary.LittleEndian.Uint32(result.Bytecode[len(result.Bytecode)-16:])
		trailerStart := result.CodeLen
		for j := 0; j < int(mapCount); j++ {
			entryOff := trailerStart + j*8
			vmOff := binary.LittleEndian.Uint32(result.Bytecode[entryOff+4:])
			if newVmOff, ok := offsetMap[int(vmOff)]; ok {
				binary.LittleEndian.PutUint32(result.Bytecode[entryOff+4:], uint32(newVmOff))
			}
		}

		// 用反转后的字节码替换原始指令区，保留 trailer
		trailer := result.Bytecode[result.CodeLen:]
		finalBytecode := make([]byte, 0, newCodeLen+len(trailer))
		finalBytecode = append(finalBytecode, reversed...)
		finalBytecode = append(finalBytecode, trailer...)
		result.Bytecode = finalBytecode
		result.CodeLen = newCodeLen

		if p.verbose {
			fmt.Printf("    [REV] reversed: %d insts, newCodeLen=%d (was %d), offsetMap entries=%d\n",
				len(offsetMap), newCodeLen, result.CodeLen, len(offsetMap))
		}

		// ---- OpcodeCryptor: 逐指令 opcode 加密 ----
		// 生成随机 oc_key (4 字节)
		var ocKeyBuf [4]byte
		if _, err := rand.Read(ocKeyBuf[:]); err != nil {
			return fmt.Errorf("generating oc_key failed: %v", err)
		}
		ocKey := binary.LittleEndian.Uint32(ocKeyBuf[:])

		// 加密字节码中每条指令的 opcode 字节 (仅 [0:CodeLen] 范围)
		// reversed=true: 每条指令后有 1B size 标记
		encryptOpcodes(result.Bytecode, result.CodeLen, ocKey, true)

		// 将 reverse 标志 + oc_key 写入 trailer 占位位置
		// trailer: [BR map entries][reverse(1B)][oc_key(4B)][map_count][func_addr][func_size]
		// reverse 位于 BR map 之后
		reverseOffset := result.CodeLen + int(mapCount)*8 // BR map 之后
		result.Bytecode[reverseOffset] = 1                // reverse = 1
		ocKeyOffset := reverseOffset + 1                  // reverse(1B) 之后
		binary.LittleEndian.PutUint32(result.Bytecode[ocKeyOffset:], ocKey)

		if p.verbose {
			fmt.Printf("    [OC] oc_key=0x%08X, codeLen=%d, mapCount=%d, reverseOff=%d, keyOff=%d\n",
				ocKey, result.CodeLen, mapCount, reverseOffset, ocKeyOffset)
		}

		// ---- XOR chain 加密 (整段字节码) ----
		xorKey := byte(0xA5)
		encrypted := make([]byte, len(result.Bytecode))
		for i, b := range result.Bytecode {
			encrypted[i] = b ^ xorKey
		}

		funcs = append(funcs, FuncBytecode{FI: fi, Encrypted: encrypted, XorKey: xorKey, reverseOffsetMap: offsetMap})
	}

	// 第二阶段: 批量注入 (一次 PT_NOTE 劫持)
	fmt.Printf("\n[*] Injecting %d functions...\n", len(funcs))
	err = p.injectVMPBatch(funcs)
	if err != nil {
		return fmt.Errorf("injection failed: %v", err)
	}

	for _, fb := range funcs {
		fmt.Printf("    [+] %s VMP protected\n", fb.FI.Name)
	}

	// 第三阶段: 清除符号表 (可选)
	if p.stripSymbols {
		p.stripSections()
		fmt.Println("[*] Symbols stripped")
	}

	err = os.WriteFile(p.outputPath, p.data, 0755)
	if err != nil {
		return fmt.Errorf("writing output failed: %v", err)
	}

	fmt.Printf("\n[+] Output: %s\n", p.outputPath)
	return nil
}

// stripSections 就地清除符号/调试 section
// stripSections 清除符号表等 section（等效 strip -s）
// 不改变文件布局和 section header 数量，只将目标 section 置空
// 同时修复其他 section 对被删除 section 的 sh_link 引用
func (p *Packer) stripSections() {
	ehdr := readEhdr64(p.data)

	// 读取 section name string table
	shstrIdx := binary.LittleEndian.Uint16(p.data[0x3E:])
	shstrOff := ehdr.Shoff + uint64(shstrIdx)*uint64(ehdr.Shentsize)
	shstrSecOff := binary.LittleEndian.Uint64(p.data[shstrOff+24:])
	shstrSecSz := binary.LittleEndian.Uint64(p.data[shstrOff+32:])

	getSectionName := func(nameOff uint32) string {
		start := shstrSecOff + uint64(nameOff)
		if start >= uint64(len(p.data)) {
			return ""
		}
		end := start
		for end < shstrSecOff+shstrSecSz && end < uint64(len(p.data)) && p.data[end] != 0 {
			end++
		}
		return string(p.data[start:end])
	}

	// 要清除的 section 名称
	stripNames := map[string]bool{
		".symtab":            true,
		".strtab":            true,
		".comment":           true,
		".note.GNU-stack":    true,
		".note.gnu.build-id": true,
	}

	// 第一遍: 收集被删除的 section index
	stripped := make(map[int]bool)
	for i := 0; i < int(ehdr.Shnum); i++ {
		shOff := ehdr.Shoff + uint64(i)*uint64(ehdr.Shentsize)
		nameOff := binary.LittleEndian.Uint32(p.data[shOff:])
		name := getSectionName(nameOff)
		if stripNames[name] {
			stripped[i] = true
		}
	}

	// 第二遍: 清零被删除的 section，修复 sh_link 引用
	for i := 0; i < int(ehdr.Shnum); i++ {
		shOff := ehdr.Shoff + uint64(i)*uint64(ehdr.Shentsize)

		if stripped[i] {
			// 读取 section 的文件偏移和大小
			secOff := binary.LittleEndian.Uint64(p.data[shOff+24:])
			secSz := binary.LittleEndian.Uint64(p.data[shOff+32:])

			// 用 0x00 清零 section 内容（等效 strip -s）
			if secOff+secSz <= uint64(len(p.data)) {
				for j := uint64(0); j < secSz; j++ {
					p.data[secOff+j] = 0
				}
			}

			nameOff := binary.LittleEndian.Uint32(p.data[shOff:])
			name := getSectionName(nameOff)

			// 清零整个 section header entry（保留 sh_name 用于调试）
			// sh_type = SHT_NULL
			binary.LittleEndian.PutUint32(p.data[shOff+4:], 0)
			// sh_flags = 0
			binary.LittleEndian.PutUint64(p.data[shOff+8:], 0)
			// sh_addr = 0
			binary.LittleEndian.PutUint64(p.data[shOff+16:], 0)
			// sh_offset = 0
			binary.LittleEndian.PutUint64(p.data[shOff+24:], 0)
			// sh_size = 0
			binary.LittleEndian.PutUint64(p.data[shOff+32:], 0)
			// sh_link = 0
			binary.LittleEndian.PutUint32(p.data[shOff+40:], 0)
			// sh_info = 0
			binary.LittleEndian.PutUint32(p.data[shOff+44:], 0)
			// sh_addralign = 0
			binary.LittleEndian.PutUint64(p.data[shOff+48:], 0)
			// sh_entsize = 0
			binary.LittleEndian.PutUint64(p.data[shOff+56:], 0)

			if p.verbose {
				fmt.Printf("    [strip] %s cleared (off=0x%X, sz=%d)\n", name, secOff, secSz)
			}
		} else {
			// 非被删除的 section: 检查 sh_link 是否指向被删除的 section
			shLink := binary.LittleEndian.Uint32(p.data[shOff+40:])
			if shLink > 0 && stripped[int(shLink)] {
				binary.LittleEndian.PutUint32(p.data[shOff+40:], 0) // 清零 sh_link
				if p.verbose {
					nameOff := binary.LittleEndian.Uint32(p.data[shOff:])
					name := getSectionName(nameOff)
					fmt.Printf("    [strip] %s: sh_link %d → 0 (target stripped)\n", name, shLink)
				}
			}
		}
	}
}

// injectVMPBatch — 批量 PT_NOTE hijack 注入
func (p *Packer) injectVMPBatch(funcs []FuncBytecode) error {
	ehdr := readEhdr64(p.data)

	// 从 blob 头部读取偏移信息
	if len(p.interpBlob) < 8 {
		return fmt.Errorf("interp blob too small: %d bytes", len(p.interpBlob))
	}

	var entryOff, tokenEntryOff, tokenTableVAOff uint64
	var interpCode []byte

	if true { /* TOKEN_ONLY: 始终使用 Token 模式 */
		// Token 模式: 24 字节扩展头
		if len(p.interpBlob) < 24 {
			return fmt.Errorf("token mode requires extended blob header (24 bytes), got %d", len(p.interpBlob))
		}
		entryOff = binary.LittleEndian.Uint64(p.interpBlob[:8])
		tokenEntryOff = binary.LittleEndian.Uint64(p.interpBlob[8:16])
		tokenTableVAOff = binary.LittleEndian.Uint64(p.interpBlob[16:24])
		interpCode = p.interpBlob[24:]
		if tokenEntryOff == 0 {
			return fmt.Errorf("vm_entry_token not found in blob (compile with -DVM_TOKEN_ENTRY)")
		}
		if tokenTableVAOff == 0 {
			return fmt.Errorf("_token_table_va not found in blob (compile with -DVM_TOKEN_ENTRY)")
		}
	}
	/* STANDARD_MODE_DISABLED: Standard header 读取已禁用
	} else {
		// 标准模式: blob 始终有 24 字节头 (vm_entry + vm_entry_token + _token_table_va)
		// 即使不使用 token 模式，也需要跳过完整头部
		if len(p.interpBlob) >= 24 {
			entryOff = binary.LittleEndian.Uint64(p.interpBlob[:8])
			interpCode = p.interpBlob[24:]
		} else {
			entryOff = binary.LittleEndian.Uint64(p.interpBlob[:8])
			interpCode = p.interpBlob[8:]
		}
	}
	STANDARD_MODE_DISABLED */

	// 1. 构造 payload: [interpCode][bc0][pad][bc1][pad][...]
	payload := make([]byte, 0, len(interpCode)+1024)
	payload = append(payload, interpCode...)
	for len(payload)%4 != 0 {
		payload = append(payload, 0x00)
	}

	type bcRecord struct {
		payloadOff int
		bcLen      int
	}
	records := make([]bcRecord, len(funcs))

	for i, fb := range funcs {
		records[i].payloadOff = len(payload)
		records[i].bcLen = len(fb.Encrypted)
		payload = append(payload, fb.Encrypted...)
		for len(payload)%4 != 0 {
			payload = append(payload, 0x00)
		}
	}

	// 2. 追加到文件末尾 (页对齐，兼容 QEMU 用户态)
	// 先将文件填充到页边界
	appendOff := uint64(len(p.data))
	padLen := (0x1000 - (appendOff % 0x1000)) % 0x1000
	for i := uint64(0); i < padLen; i++ {
		p.data = append(p.data, 0x00)
	}
	payloadFileOff := uint64(len(p.data)) // 现在是页对齐的
	// 动态计算 payloadVA: 扫描所有 LOAD 段，取最高 Vaddr+Memsz，向上对齐到 64KB
	var maxVA uint64
	for i := 0; i < int(ehdr.Phnum); i++ {
		phOff := ehdr.Phoff + uint64(i)*uint64(ehdr.Phentsize)
		ph := readPhdr64(p.data, phOff)
		if ph.Type == uint32(elf.PT_LOAD) {
			end := ph.Vaddr + ph.Memsz
			if end > maxVA {
				maxVA = end
			}
		}
	}
	payloadVA := (maxVA + 0xFFFF) &^ 0xFFFF // 向上对齐到 64KB 边界

	p.data = append(p.data, payload...)

	interpVA := payloadVA + entryOff // vm_entry 偏移由 Makefile 自动注入到 blob 头部

	fmt.Printf("    Payload at file offset: 0x%X, VA: 0x%X, size: %d\n",
		payloadFileOff, payloadVA, len(payload))
	fmt.Printf("    VM interp VA: 0x%X\n", interpVA)

	for i, fb := range funcs {
		bcVA := payloadVA + uint64(records[i].payloadOff)
		fmt.Printf("    [%s] bytecode VA: 0x%X, len: %d\n",
			fb.FI.Name, bcVA, records[i].bcLen)
	}

	// 3. 找到 PT_NOTE 段并劫持为 PT_LOAD
	noteIdx := -1
	for i := 0; i < int(ehdr.Phnum); i++ {
		phOff := ehdr.Phoff + uint64(i)*uint64(ehdr.Phentsize)
		ph := readPhdr64(p.data, phOff)
		if ph.Type == uint32(elf.PT_NOTE) {
			noteIdx = i
			break
		}
	}
	if noteIdx < 0 {
		return fmt.Errorf("PT_NOTE segment not found")
	}

	// 4. PT_NOTE → PT_LOAD (RX)
	notePhdrOff := ehdr.Phoff + uint64(noteIdx)*uint64(ehdr.Phentsize)
	newPhdr := elf64Phdr{
		Type:   uint32(elf.PT_LOAD),
		Flags:  uint32(elf.PF_R | elf.PF_X),
		Off:    payloadFileOff,
		Vaddr:  payloadVA,
		Paddr:  payloadVA,
		Filesz: uint64(len(payload)),
		Memsz:  uint64(len(payload)),
		Align:  0x1000,
	}
	writePhdr64(p.data, notePhdrOff, newPhdr)

	fmt.Printf("    PT_NOTE[%d] -> PT_LOAD RX: off=0x%X va=0x%X sz=0x%X\n",
		noteIdx, payloadFileOff, payloadVA, len(payload))

	// 4b. 按 Vaddr 升序重排所有 PT_LOAD 段，防止内核映射 BSS 失败
	{
		type phdrSlot struct {
			idx  int
			phdr elf64Phdr
		}
		var loads []phdrSlot
		for i := 0; i < int(ehdr.Phnum); i++ {
			off := ehdr.Phoff + uint64(i)*uint64(ehdr.Phentsize)
			ph := readPhdr64(p.data, off)
			if ph.Type == uint32(elf.PT_LOAD) {
				loads = append(loads, phdrSlot{idx: i, phdr: ph})
			}
		}
		// 检查是否需要重排
		needSort := false
		for k := 1; k < len(loads); k++ {
			if loads[k].phdr.Vaddr < loads[k-1].phdr.Vaddr {
				needSort = true
				break
			}
		}
		if needSort {
			// 按 Vaddr 排序 PHDR 内容
			sort.Slice(loads, func(a, b int) bool {
				return loads[a].phdr.Vaddr < loads[b].phdr.Vaddr
			})
			// 收集原始 PHDR 槽位索引（按在 PHDR 表中出现的顺序）
			slotIndices := make([]int, len(loads))
			for k := range loads {
				slotIndices[k] = loads[k].idx
			}
			sort.Ints(slotIndices)
			// 将排序后的 PHDR 内容写回原始槽位
			for k, si := range slotIndices {
				off := ehdr.Phoff + uint64(si)*uint64(ehdr.Phentsize)
				writePhdr64(p.data, off, loads[k].phdr)
			}
			fmt.Printf("    [PHDR] Reordered %d PT_LOAD segments by Vaddr ascending\n", len(loads))
			// 更新 notePhdrOff — 找到 payload 段的新位置
			for i := 0; i < int(ehdr.Phnum); i++ {
				off := ehdr.Phoff + uint64(i)*uint64(ehdr.Phentsize)
				ph := readPhdr64(p.data, off)
				if ph.Type == uint32(elf.PT_LOAD) && ph.Vaddr == payloadVA {
					notePhdrOff = off
					break
				}
			}
		}
	}

	// 5. 为每个函数写跳板 + 销毁原始代码
	if true { /* TOKEN_ONLY: 始终使用 Token 跳板 */
		// ---- Token 模式 ----

		// 5a. 构建 token_desc_t 描述符表
		// 8-byte 对齐
		for len(payload)%8 != 0 {
			payload = append(payload, 0x00)
		}

		// 获取 函数num == token_desc_t num，写入 token_desc_t num (8 bytes)，后续紧跟 token_desc_t 表
		var desc_num [8]byte
		funcs_num := len(funcs)
		binary.LittleEndian.PutUint64(desc_num[0:], (uint64)(funcs_num))
		payload = append(payload, desc_num[:]...)

		tokenTableOff := len(payload)
		tokenTableVA := payloadVA + uint64(tokenTableOff)

		// 每个函数一个 token_desc_t (16 bytes): bc_off(u64) + bc_len(u32) + reserved(u32)
		// bc_off = 相对于 _token_table_va 自身地址的偏移 (PIE 兼容)
		selfVA := payloadVA + tokenTableVAOff // _token_table_va 的 VA
		for i := range funcs {
			bcVA := payloadVA + uint64(records[i].payloadOff)
			bcLen := uint32(records[i].bcLen)

			var desc [16]byte
			binary.LittleEndian.PutUint64(desc[0:], bcVA-selfVA) // 相对偏移
			binary.LittleEndian.PutUint32(desc[8:], bcLen)
			binary.LittleEndian.PutUint32(desc[12:], 0) // reserved
			payload = append(payload, desc[:]...)
		}

		// 写入 so name信息（在 token_desc_t 表后面）供运行时获取so基地址
		// [so_name_len][so_name][0]
		soNameLen := len(p.soName)
		payload = append(payload, byte(soNameLen))
		payload = append(payload, []byte(p.soName)...)
		payload = append(payload, 0)

		// 添加自定义重定位表（处理重定位信息，供运行时修复）
		if len(p.relocations) > 0 {
			fmt.Printf("    [RELOC] Processing %d relocations...\n", len(p.relocations))

			var runtimeRelocs []RuntimeReloc

			// 处理重定位
			for i, fb := range funcs {
				// 获取每一个函数的所有重定位信息
				funcRelocs := p.getRelocationsForFunc(fb.FI.Name)
				for _, reloc := range funcRelocs {
					// 处理每一条重定位信息
					// 通过原始偏移得到反转后的偏移
					reOff := (uint64)(fb.reverseOffsetMap[(int)(reloc.BcOffset)])
					// 反转后的偏移指向当前指令末尾，因为每条指令多了 1B size 标记，待重定位指令最后8b 为操作数（待重定位地址）
					// 所以 待重定位地址当前在 byteCode 中的偏移为 reOff - 1 - 8
					writePos := reOff - 9

					fmt.Printf("    [RELOC] reloc.Offset : %d,  new reloc.Offset : %d\n", reloc.BcOffset, writePos)
					// .so 中地址是相对的，需要运行时加上基址
					// 记录需要运行时加基址
					runtimeRelocs = append(runtimeRelocs, RuntimeReloc{
						WritePos: writePos,
						Offset:   reloc.TargetAddr,
						FuncId:   (uint64)(i),
					})
				}
			}

			// 将运行时重定位表附加到 so_name_info 后面
			table := p.appendRuntimeRelocTable(runtimeRelocs)
			payload = append(payload, table...)

			fmt.Printf("\n重定位表总大小: %d 字节\n", len(table))
			fmt.Printf("=====================================\n")
		}

		// 更新 PT_LOAD 段大小 (payload 增长了)
		newPhdr.Filesz = uint64(len(payload))
		newPhdr.Memsz = uint64(len(payload))
		writePhdr64(p.data, notePhdrOff, newPhdr)

		// 重新追加 payload 到文件 (覆盖之前的)
		p.data = p.data[:payloadFileOff]
		p.data = append(p.data, payload...)

		// 5b. Patch _token_table_va: 存储相对于自身地址的偏移 (PIE 兼容)
		// selfVA = payloadVA + tokenTableVAOff (已在上面计算)
		tblRelOff := tokenTableVA - selfVA
		binary.LittleEndian.PutUint64(p.data[payloadFileOff+tokenTableVAOff:], tblRelOff)

		fmt.Printf("    [TOKEN] descriptor table VA: 0x%X, entries: %d\n", tokenTableVA, len(funcs))
		fmt.Printf("    [TOKEN] _token_table_va patched at blob offset 0x%X → relative offset 0x%X (PIE)\n", tokenTableVAOff, tblRelOff)

		// 5c. 为每个函数生成 Token trampoline
		vmEntryTokenVA := payloadVA + tokenEntryOff
		fmt.Printf("    [TOKEN] vm_entry_token VA: 0x%X\n", vmEntryTokenVA)

		for i, fb := range funcs {
			funcID := uint32(i) // func_id = 序号 (0-based)
			token := (uint32(fb.XorKey) << 24) | (0 << 12) | (funcID & 0xFFF)

			trampoline := BuildTokenTrampoline(fb.FI.Addr, vmEntryTokenVA, token)
			if uint64(len(trampoline)) > fb.FI.Size {
				return fmt.Errorf("token trampoline for %s (%d bytes) exceeds function size (%d bytes)",
					fb.FI.Name, len(trampoline), fb.FI.Size)
			}

			// 写入跳板
			for j := 0; j < len(trampoline); j++ {
				p.data[fb.FI.Offset+uint64(j)] = trampoline[j]
			}

			// 销毁剩余原始代码
			garbageLen := int(fb.FI.Size) - len(trampoline)
			if garbageLen > 0 {
				garbage := make([]byte, garbageLen)
				rand.Read(garbage)
				copy(p.data[fb.FI.Offset+uint64(len(trampoline)):], garbage)
			}

			fmt.Printf("    [TOKEN] %s: func_id=%d, token=0x%08X, trampoline=%d bytes\n",
				fb.FI.Name, funcID, token, len(trampoline))
		}
	}
	/* STANDARD_MODE_DISABLED: Token 模式为唯一入口，Standard 模式已禁用
	} else {
		// ---- 标准模式 ----
		for i, fb := range funcs {
			bcVA := payloadVA + uint64(records[i].payloadOff)
			bcLen := uint32(records[i].bcLen)

			trampoline := BuildTrampoline(fb.FI.Addr, interpVA, bcVA, bcLen, fb.XorKey)
			if uint64(len(trampoline)) > fb.FI.Size {
				return fmt.Errorf("trampoline for %s (%d bytes) exceeds function size (%d bytes)",
					fb.FI.Name, len(trampoline), fb.FI.Size)
			}

			// 写入跳板
			for j := 0; j < len(trampoline); j++ {
				p.data[fb.FI.Offset+uint64(j)] = trampoline[j]
			}

			// 用随机垃圾字节彻底销毁跳板后的原始代码
			garbageLen := int(fb.FI.Size) - len(trampoline)
			if garbageLen > 0 {
				garbage := make([]byte, garbageLen)
				rand.Read(garbage)
				copy(p.data[fb.FI.Offset+uint64(len(trampoline)):], garbage)
			}

			if p.verbose {
				fmt.Printf("    [%s] Trampoline (%d bytes) + Garbage (%d bytes):\n",
					fb.FI.Name, len(trampoline), garbageLen)
				for j := 0; j < len(trampoline); j += 4 {
					inst := binary.LittleEndian.Uint32(trampoline[j:])
					fmt.Printf("      +%02X: 0x%08X\n", j, inst)
				}
			}
		}
	}
	STANDARD_MODE_DISABLED */

	return nil
}

func (p *Packer) getRelocationsForFunc(funcName string) []arm64.Relocation {
	var result []arm64.Relocation
	for _, r := range p.relocations {
		if r.FuncName == funcName {
			result = append(result, r)
		}
	}
	return result
}

// 生成运行时重定位表
func (p *Packer) appendRuntimeRelocTable(relocs []RuntimeReloc) []byte {
	// 格式: [magic:4][count:4][entries...]
	// entry: [func_id:8][write_pos:8][offset:8]
	fmt.Printf("\n========== 生成运行时重定位表 ==========\n")
	fmt.Printf("重定位条目数量: %d\n", len(relocs))

	table := []byte{}

	// 魔数 "RTLR" (Runtime ReLoc)
	table = append(table, []byte{'R', 'T', 'L', 'R'}...)
	fmt.Printf("魔数: RTLR (0x524C5452)\n")

	// 数量
	countBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBuf, uint32(len(relocs)))
	table = append(table, countBuf...)
	fmt.Printf("条目数量: %d (0x%X)\n", len(relocs), len(relocs))

	fmt.Printf("\n重定位条目详情:\n")
	for i, reloc := range relocs {
		// 函数 id
		funcIdBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(funcIdBuf, reloc.FuncId)
		table = append(table, funcIdBuf...)
		// 写入位置
		posBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(posBuf, reloc.WritePos)
		table = append(table, posBuf...)
		// 偏移
		offBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(offBuf, reloc.Offset)
		table = append(table, offBuf...)
		fmt.Printf("      函数id: %d\n", reloc.FuncId)
		fmt.Printf("  [%d] 写入位置: 0x%X\n", i, reloc.WritePos)
		fmt.Printf("      偏移: 0x%X\n", reloc.Offset)
		fmt.Printf("      偏移(hex): % X\n", offBuf)
	}

	return table
}

// PrintELFInfo 打印 ELF 信息
func PrintELFInfo(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Printf("ELF: %s\n", path)
	fmt.Printf("  Arch: %s, Type: %s, Entry: 0x%X\n", f.Machine, f.Type, f.Entry)

	fmt.Println("\n  Sections:")
	for _, s := range f.Sections {
		if s.Size > 0 {
			fmt.Printf("    %-16s  Addr=0x%08X  Size=0x%X  Off=0x%X\n",
				s.Name, s.Addr, s.Size, s.Offset)
		}
	}

	fmt.Println("\n  Program Headers:")
	raw, _ := os.ReadFile(path)
	if len(raw) >= 64 {
		ehdr := readEhdr64(raw)
		for i := 0; i < int(ehdr.Phnum); i++ {
			ph := readPhdr64(raw, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
			flags := ""
			if ph.Flags&uint32(elf.PF_R) != 0 {
				flags += "R"
			}
			if ph.Flags&uint32(elf.PF_W) != 0 {
				flags += "W"
			}
			if ph.Flags&uint32(elf.PF_X) != 0 {
				flags += "X"
			}
			fmt.Printf("    [%d] Type=0x%X Flags=%s Off=0x%X VA=0x%X FileSz=0x%X MemSz=0x%X\n",
				i, ph.Type, flags, ph.Off, ph.Vaddr, ph.Filesz, ph.Memsz)
		}
	}

	fmt.Println("\n  Functions:")
	syms, err := f.Symbols()
	if err != nil {
		fmt.Println("  (no symbol table)")
		return nil
	}
	count := 0
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Size > 0 {
			fmt.Printf("    %-24s  Addr=0x%08X  Size=%d\n",
				sym.Name, sym.Value, sym.Size)
			count++
		}
	}
	fmt.Printf("  Total: %d functions\n", count)
	return nil
}

// branchTargetOffset 返回分支指令中 target32 相对于 pc 的字节偏移
// 标准分支: [op(1B)][target32(4B)] = 5B → offset=1
// TBZ/TBNZ: [op(1B)][reg(1B)][bit(1B)][target32(4B)] = 7B → offset=3
// 非分支指令返回 0
func branchTargetOffset(op byte) int {
	switch op {
	case vm.OpJmp, vm.OpJe, vm.OpJne, vm.OpJl, vm.OpJge,
		vm.OpJgt, vm.OpJle, vm.OpJb, vm.OpJae, vm.OpJbe, vm.OpJa:
		return 1
	case vm.OpTbz, vm.OpTbnz:
		return 3
	}
	return 0
}

// reverseInstructions 反转指令顺序并追加 size 标记
//
// 输入: bytecode[0:codeLen] 为纯指令区 (不含 trailer)
// 输出: 反转后的字节码 + old_offset→new_offset 映射
//
// 反转后每条指令后追加 1 字节 size 标记:
//
//	[inst_N bytes][size_N(1B)][inst_N-1 bytes][size_N-1(1B)]...
//
// stub 解释器反向遍历: pc--; size=bc[pc]; pc-=size; → 定位到指令起始
func reverseInstructions(bytecode []byte, codeLen int) ([]byte, map[int]int) {
	// 1. 解析所有指令的 (offset, size)
	type instInfo struct {
		offset int
		size   int
	}
	var insts []instInfo
	pc := 0
	totalOrigBytes := 0
	for pc < codeLen {
		op := bytecode[pc]
		sz := vm.InstructionSize(op)
		if sz == 0 {
			sz = 1 // 未知 opcode fallback
		}
		if pc+sz > codeLen {
			break
		}
		insts = append(insts, instInfo{offset: pc, size: sz})
		totalOrigBytes += sz
		pc += sz
	}

	// 2. 反转顺序，追加 size 标记，构建 offset 映射
	offsetMap := make(map[int]int) // old_offset → new_offset
	var reversed []byte
	for i := len(insts) - 1; i >= 0; i-- {
		inst := insts[i]
		newOffset := len(reversed)
		// 复制指令字节
		reversed = append(reversed, bytecode[inst.offset:inst.offset+inst.size]...)
		// 追加 1 字节 size 标记
		reversed = append(reversed, byte(inst.size))
		// offsetMap 指向 size_marker 之后的位置 (DISPATCH 期望 pc 在此处)
		// DISPATCH: pc-- → size_marker, size=bc[pc], pc-=size → 指令起始
		offsetMap[inst.offset] = newOffset + inst.size + 1
	}

	return reversed, offsetMap
}

// remapBranchTargets 重映射反转后字节码中的分支目标
//
// 扫描 reversed bytecode，找到所有分支指令，
// 将其 target32 从旧偏移替换为新偏移 (使用 offsetMap)
func remapBranchTargets(bytecode []byte, codeLen int, offsetMap map[int]int, verbose bool) {
	pc := 0
	for pc < codeLen {
		op := bytecode[pc]
		sz := vm.InstructionSize(op)
		if sz == 0 {
			sz = 1
		}
		if toff := branchTargetOffset(op); toff > 0 && pc+toff+4 <= codeLen {
			oldTarget := binary.LittleEndian.Uint32(bytecode[pc+toff:])
			if newTarget, ok := offsetMap[int(oldTarget)]; ok {
				if verbose {
					fmt.Printf("      [REMAP] pc=0x%04X op=0x%02X target: 0x%04X → 0x%04X\n",
						pc, op, oldTarget, newTarget)
				}
				binary.LittleEndian.PutUint32(bytecode[pc+toff:], uint32(newTarget))
			} else if verbose {
				fmt.Printf("      [REMAP] pc=0x%04X op=0x%02X target: 0x%04X → NOT FOUND!\n",
					pc, op, oldTarget)
			}
		}
		// 跳过指令 + size 标记 (反转后每条指令后有 1B size)
		pc += sz + 1
	}
}

// encryptOpcodes 逐指令加密 opcode 字节 (OpcodeCryptor)
//
// 遍历 bytecode[0:codeLen]，使用 vm.InstructionSize 确定每条指令的大小，
// 只加密每条指令的第一个字节 (opcode)，操作数不变。
//
// reversed=true 时，每条指令后有 1B size 标记，步进为 size+1
//
// 加密公式: encrypted_opcode[pc] = opcode[pc] ^ (u8)(ocKey ^ (pc * 0x9E3779B9))
func encryptOpcodes(bytecode []byte, codeLen int, ocKey uint32, reversed bool) {
	pc := 0
	for pc < codeLen {
		op := bytecode[pc]
		size := vm.InstructionSize(op)
		if size == 0 {
			// 未知 opcode，跳过 1 字节 (不应发生)
			pc++
			continue
		}
		// 加密 opcode 字节
		mask := byte(ocKey ^ (uint32(pc) * 0x9E3779B9))
		bytecode[pc] = op ^ mask
		// 跳到下一条指令
		if reversed {
			pc += size + 1 // +1 for size marker byte
		} else {
			pc += size
		}
	}
}
