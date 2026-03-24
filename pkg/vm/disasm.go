package vm

import (
	"encoding/binary"
	"fmt"
)

// ============================================================
// VM 字节码反汇编器
//
// 将 VM 字节码解码为可读文本，用于 debug 对照输出。
// 格式对齐 vm_opcodes.h 注释风格。
// ============================================================

// opInfo 操作码信息
type opInfo struct {
	Name string
	Size int // 指令总字节数 (0 = 可变)
}

var opTable = map[byte]opInfo{
	OpNop:      {"NOP", 1},
	OpMovImm:   {"MOV_IMM64", 10}, // op + r + imm64
	OpMovImm32: {"MOV_IMM32", 6},  // op + r + imm32
	OpMovReg:   {"MOV_REG", 3},    // op + dst + src

	OpLoad8:   {"LOAD8", 5}, // op + dst + base + imm16
	OpLoad32:  {"LOAD32", 5},
	OpLoad64:  {"LOAD64", 5},
	OpStore8:  {"STORE8", 5},
	OpStore32: {"STORE32", 5},
	OpStore64: {"STORE64", 5},
	OpLoad16:  {"LOAD16", 5},
	OpStore16: {"STORE16", 5},

	OpAdd:   {"ADD", 4}, // op + d + a + b
	OpSub:   {"SUB", 4},
	OpMul:   {"MUL", 4},
	OpXor:   {"XOR", 4},
	OpAnd:   {"AND", 4},
	OpOr:    {"OR", 4},
	OpShl:   {"SHL", 4},
	OpShr:   {"SHR", 4},
	OpAsr:   {"ASR", 4},
	OpNot:   {"NOT", 3}, // op + dst + src
	OpRor:   {"ROR", 4},
	OpUmulh: {"UMULH", 4},

	OpAddImm: {"ADD_IMM", 7}, // op + d + s + imm32
	OpSubImm: {"SUB_IMM", 7},
	OpXorImm: {"XOR_IMM", 7},
	OpAndImm: {"AND_IMM", 7},
	OpOrImm:  {"OR_IMM", 7},
	OpMulImm: {"MUL_IMM", 7},
	OpShlImm: {"SHL_IMM", 7},
	OpShrImm: {"SHR_IMM", 7},
	OpAsrImm: {"ASR_IMM", 7},

	OpCmp:    {"CMP", 3},     // op + rx + ry
	OpCmpImm: {"CMP_IMM", 6}, // op + rx + imm32

	OpJmp: {"JMP", 5}, // op + imm32
	OpJe:  {"JE", 5},
	OpJne: {"JNE", 5},
	OpJl:  {"JL", 5},
	OpJge: {"JGE", 5},
	OpJgt: {"JGT", 5},
	OpJle: {"JLE", 5},
	OpJb:  {"JB", 5},
	OpJae: {"JAE", 5},
	OpJbe: {"JBE", 5},
	OpJa:  {"JA", 5},

	OpPush: {"PUSH", 2}, // op + rx
	OpPop:  {"POP", 2},

	OpCallNative: {"CALL_NATIVE", 9}, // op + imm64
	OpCallReg:    {"CALL_REG", 2},    // op + rn (BLR)
	OpBrReg:      {"BR_REG", 2},      // op + rn (BR)
	OpRet:        {"RET", 2},         // op + rx
	OpHalt:       {"HALT", 1},

	OpVld16: {"VLD16", 3}, // op + rn + len
	OpVst16: {"VST16", 3},

	OpTbz:  {"TBZ", 7}, // op + reg + bit + target32
	OpTbnz: {"TBNZ", 7},

	OpCcmpReg: {"CCMP_REG", 6}, // op + cond + nzcv + rn + rm + sf
	OpCcmpImm: {"CCMP_IMM", 6},
	OpCcmnReg: {"CCMN_REG", 6},
	OpCcmnImm: {"CCMN_IMM", 6},

	OpSvc: {"SVC", 3}, // op + imm16

	OpUdiv: {"UDIV", 4}, // op + d + n + m
	OpSdiv: {"SDIV", 4}, // op + d + n + m
	OpMrs:  {"MRS", 4},  // op + d + sysreg_lo + sysreg_hi

	OpSmulh: {"SMULH", 4}, // op + d + n + m
	OpClz:   {"CLZ", 3},   // op + d + n
	OpCls:   {"CLS", 3},
	OpRbit:  {"RBIT", 3},
	OpRev:   {"REV", 3},
	OpRev16: {"REV16", 3},
	OpRev32: {"REV32", 3},

	OpAdc: {"ADC", 4}, // op + d + n + m
	OpSbc: {"SBC", 4},

	// ---- 栈机器操作码 ----
	OpSVload:      {"S_VLOAD", 2},  // op + r
	OpSVstore:     {"S_VSTORE", 2}, // op + r
	OpSPushImm32:  {"S_PUSH32", 5}, // op + imm32
	OpSPushImm64:  {"S_PUSH64", 9}, // op + imm64
	OpSDup:        {"S_DUP", 1},
	OpSSwap:       {"S_SWAP", 1},
	OpSDrop:       {"S_DROP", 1},
	OpSAdd:        {"S_ADD", 1},
	OpSSub:        {"S_SUB", 1},
	OpSMul:        {"S_MUL", 1},
	OpSXor:        {"S_XOR", 1},
	OpSAnd:        {"S_AND", 1},
	OpSOr:         {"S_OR", 1},
	OpSShl:        {"S_SHL", 1},
	OpSShr:        {"S_SHR", 1},
	OpSAsr:        {"S_ASR", 1},
	OpSRor:        {"S_ROR", 1},
	OpSUmulh:      {"S_UMULH", 1},
	OpSSmulh:      {"S_SMULH", 1},
	OpSUdiv:       {"S_UDIV", 1},
	OpSSdiv:       {"S_SDIV", 1},
	OpSAdc:        {"S_ADC", 1},
	OpSSbc:        {"S_SBC", 1},
	OpSNot:        {"S_NOT", 1},
	OpSClz:        {"S_CLZ", 1},
	OpSCls:        {"S_CLS", 1},
	OpSRbit:       {"S_RBIT", 1},
	OpSRev:        {"S_REV", 1},
	OpSRev16:      {"S_REV16", 1},
	OpSRev32:      {"S_REV32", 1},
	OpSTrunc32:    {"S_TRUNC32", 1},
	OpSSext32:     {"S_SEXT32", 1},
	OpSCmp:        {"S_CMP", 1},
	OpSLd8:        {"S_LD8", 1},
	OpSLd16:       {"S_LD16", 1},
	OpSLd32:       {"S_LD32", 1},
	OpSLd64:       {"S_LD64", 1},
	OpSSt8:        {"S_ST8", 1},
	OpSSt16:       {"S_ST16", 1},
	OpSSt32:       {"S_ST32", 1},
	OpSSt64:       {"S_ST64", 1},
	OpSAdSetflags: {"S_AdSetflags", 1},
	OpSSuSetflags: {"S_SuSetflags", 1},
	OpSAnSetflags: {"S_AnSetflags", 1},
}

// InstructionSize 返回指定 opcode 的指令总字节数 (0 = 未知)
func InstructionSize(op byte) int {
	if info, ok := opTable[op]; ok {
		return info.Size
	}
	return 0
}

// OpcodeName 操作码→名称
func OpcodeName(op byte) string {
	if info, ok := opTable[op]; ok {
		return info.Name
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", op)
}

// DisasmOne 反汇编一条 VM 指令
// 返回可读文本和指令字节数
func DisasmOne(code []byte, pc int) (string, int) {
	if pc >= len(code) {
		return "EOF", 0
	}
	op := code[pc]
	info, known := opTable[op]
	if !known {
		return fmt.Sprintf("%04X: UNKNOWN 0x%02X", pc, op), 1
	}

	remain := len(code) - pc
	if info.Size > remain {
		return fmt.Sprintf("%04X: %s (truncated)", pc, info.Name), remain
	}

	switch op {
	case OpNop:
		return fmt.Sprintf("%04X: NOP", pc), 1
	case OpHalt:
		return fmt.Sprintf("%04X: HALT", pc), 1

	case OpMovImm:
		r := code[pc+1]
		v := binary.LittleEndian.Uint64(code[pc+2:])
		return fmt.Sprintf("%04X: MOV R%d, 0x%X", pc, r, v), 10

	case OpMovImm32:
		r := code[pc+1]
		v := binary.LittleEndian.Uint32(code[pc+2:])
		return fmt.Sprintf("%04X: MOV32 R%d, 0x%X", pc, r, v), 6

	case OpMovReg:
		return fmt.Sprintf("%04X: MOV R%d, R%d", pc, code[pc+1], code[pc+2]), 3

	case OpLoad8, OpLoad16, OpLoad32, OpLoad64:
		dst := code[pc+1]
		base := code[pc+2]
		imm := binary.LittleEndian.Uint16(code[pc+3:])
		width := map[byte]string{OpLoad8: "8", OpLoad16: "16", OpLoad32: "32", OpLoad64: "64"}[op]
		return fmt.Sprintf("%04X: LOAD%s R%d, [R%d + %d]", pc, width, dst, base, imm), 5

	case OpStore8, OpStore16, OpStore32, OpStore64:
		base := code[pc+1]
		src := code[pc+2]
		imm := binary.LittleEndian.Uint16(code[pc+3:])
		width := map[byte]string{OpStore8: "8", OpStore16: "16", OpStore32: "32", OpStore64: "64"}[op]
		return fmt.Sprintf("%04X: STORE%s [R%d + %d], R%d", pc, width, base, imm, src), 5

	case OpAdd, OpSub, OpMul, OpXor, OpAnd, OpOr, OpShl, OpShr, OpAsr, OpRor, OpUmulh, OpUdiv, OpSdiv, OpSmulh, OpAdc, OpSbc:
		return fmt.Sprintf("%04X: %s R%d, R%d, R%d",
			pc, info.Name, code[pc+1], code[pc+2], code[pc+3]), 4

	case OpNot, OpClz, OpCls, OpRbit, OpRev, OpRev16, OpRev32:
		return fmt.Sprintf("%04X: %s R%d, R%d", pc, info.Name, code[pc+1], code[pc+2]), 3

	case OpAddImm, OpSubImm, OpXorImm, OpAndImm, OpOrImm, OpMulImm, OpShlImm, OpShrImm, OpAsrImm:
		d := code[pc+1]
		s := code[pc+2]
		imm := binary.LittleEndian.Uint32(code[pc+3:])
		return fmt.Sprintf("%04X: %s R%d, R%d, 0x%X", pc, info.Name, d, s, imm), 7

	case OpCmp:
		return fmt.Sprintf("%04X: CMP R%d, R%d", pc, code[pc+1], code[pc+2]), 3

	case OpCmpImm:
		r := code[pc+1]
		imm := binary.LittleEndian.Uint32(code[pc+2:])
		return fmt.Sprintf("%04X: CMP R%d, 0x%X", pc, r, imm), 6

	case OpJmp, OpJe, OpJne, OpJl, OpJge, OpJgt, OpJle, OpJb, OpJae, OpJbe, OpJa:
		target := binary.LittleEndian.Uint32(code[pc+1:])
		return fmt.Sprintf("%04X: %s 0x%04X", pc, info.Name, target), 5

	case OpPush:
		return fmt.Sprintf("%04X: PUSH R%d", pc, code[pc+1]), 2
	case OpPop:
		return fmt.Sprintf("%04X: POP R%d", pc, code[pc+1]), 2

	case OpCallNative:
		target := binary.LittleEndian.Uint64(code[pc+1:])
		return fmt.Sprintf("%04X: CALL 0x%X", pc, target), 9

	case OpCallReg:
		return fmt.Sprintf("%04X: BLR R%d", pc, code[pc+1]), 2

	case OpBrReg:
		return fmt.Sprintf("%04X: BR R%d", pc, code[pc+1]), 2

	case OpRet:
		return fmt.Sprintf("%04X: RET R%d", pc, code[pc+1]), 2

	case OpVld16:
		return fmt.Sprintf("%04X: VLD16 R%d, %d", pc, code[pc+1], code[pc+2]), 3
	case OpVst16:
		return fmt.Sprintf("%04X: VST16 R%d, %d", pc, code[pc+1], code[pc+2]), 3

	case OpTbz, OpTbnz:
		reg := code[pc+1]
		bit := code[pc+2]
		target := binary.LittleEndian.Uint32(code[pc+3:])
		return fmt.Sprintf("%04X: %s R%d, #%d, 0x%04X", pc, info.Name, reg, bit, target), 7

	case OpCcmpReg, OpCcmpImm, OpCcmnReg, OpCcmnImm:
		cond := code[pc+1]
		nzcv := code[pc+2]
		rn := code[pc+3]
		rmOrImm := code[pc+4]
		sf := code[pc+5]
		if op == OpCcmpImm || op == OpCcmnImm {
			return fmt.Sprintf("%04X: %s R%d, #%d, #%d, cond=%d sf=%d", pc, info.Name, rn, rmOrImm, nzcv, cond, sf), 6
		}
		return fmt.Sprintf("%04X: %s R%d, R%d, #%d, cond=%d sf=%d", pc, info.Name, rn, rmOrImm, nzcv, cond, sf), 6

	case OpSvc:
		imm := binary.LittleEndian.Uint16(code[pc+1:])
		return fmt.Sprintf("%04X: SVC #0x%X", pc, imm), 3

	case OpMrs:
		dst := code[pc+1]
		sysreg := binary.LittleEndian.Uint16(code[pc+2:])
		return fmt.Sprintf("%04X: MRS R%d, sysreg=0x%04X", pc, dst, sysreg), 4

	default:
		return fmt.Sprintf("%04X: %s", pc, info.Name), info.Size
	}
}

// DisasmRange 反汇编指定范围的字节码
func DisasmRange(code []byte, start, end int) []string {
	var lines []string
	pc := start
	for pc < end && pc < len(code) {
		text, size := DisasmOne(code, pc)
		if size == 0 {
			break
		}
		lines = append(lines, text)
		pc += size
	}
	return lines
}

// DisasmAll 反汇编整段字节码
func DisasmAll(code []byte) []string {
	return DisasmRange(code, 0, len(code))
}
