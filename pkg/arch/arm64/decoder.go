package arm64

import (
	"fmt"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ARM64 (AArch64) 指令解码器 v3 — 表驱动架构
//
// 基于 ARM Architecture Reference Manual 的顶层分组：
//   op0[3:0] = bits[28:25]
//
// 解码流程:
//   raw → op0 分组 → matchAndDecode(模式表) → vm.Instruction
//
// 模式表定义在以下文件中：
//   decode_dp_imm.go  — 数据处理(立即数)
//   decode_dp_reg.go  — 数据处理(寄存器)
//   decode_branch.go  — 分支/系统
//   decode_ldst.go    — 加载/存储
//
// 核心引擎:
//   decode_fields.go  — FieldDef/InstrPattern + 匹配/提取
// ============================================================

// Op ARM64 指令操作码
type Op int

const (
	UNKNOWN Op = iota
	ADD_IMM
	SUB_IMM
	ADDS_IMM
	SUBS_IMM
	AND_IMM
	ORR_IMM
	EOR_IMM
	MOVZ
	MOVK
	MOVN
	ADD_REG
	SUB_REG
	ADDS_REG
	SUBS_REG
	AND_REG
	ORR_REG
	EOR_REG
	EON
	ANDS_REG
	LSL_REG
	LSR_REG
	ASR_REG
	ROR_REG
	MUL
	SDIV
	UDIV
	MVN
	UBFM
	SBFM
	LDR_IMM
	LDRB_IMM
	LDRH_IMM
	LDRSB_IMM
	LDRSH_IMM
	LDRSW_IMM
	STR_IMM
	STRB_IMM
	STRH_IMM
	LDP
	STP
	LDR_LIT
	LDR_REG
	LDRB_REG
	STRB_REG
	STR_REG
	B
	BL
	BR
	BLR
	RET
	B_COND
	CBZ
	CBNZ
	TBZ
	TBNZ
	CSEL
	CSINC
	CSINV
	CSNEG
	ADR
	ADRP
	NOP
	SVC
	MADD
	MSUB
	UMULH
	SMADDL
	SMSUBL
	UMADDL
	UMSUBL
	EXTR
	LD1_16B
	ST1_16B
	ADD_EXT
	SUB_EXT
	ADDS_EXT
	SUBS_EXT
	CCMP_REG
	CCMP_IMM
	CCMN_REG
	CCMN_IMM
	ANDS_IMM
	MRS
	LDRH_REG
	STRH_REG
	LDRSB_REG
	LDRSH_REG
	LDRSW_REG
	BIC
	BICS
	ORN
	BFM
	SMULH
	CLZ
	CLS
	RBIT
	REV
	REV16
	REV32
	ADC
	ADCS
	SBC
	SBCS
	DMB
	DSB
	ISB
	WFE
	WFI
	YIELD_ARM
	CLREX
	HLT
	BRK
	MSR_WRITE
	PRFM
	LDAR
	STLR
	LDAXR
	STLXR
	LDPSW
	LDADD
	CAS
	PACIASP
	AUTIASP
	PACIAZ
	AUTIAZ
	PACIBSP
	AUTIBSP
	XPACLRI
	BTI_C
	BTI_J
	BTI_JC
	BTI
	UNSUPPORTED
)

// 条件码
const (
	COND_EQ = 0x0
	COND_NE = 0x1
	COND_CS = 0x2
	COND_CC = 0x3
	COND_MI = 0x4
	COND_PL = 0x5
	COND_VS = 0x6
	COND_VC = 0x7
	COND_HI = 0x8
	COND_LS = 0x9
	COND_GE = 0xA
	COND_LT = 0xB
	COND_GT = 0xC
	COND_LE = 0xD
	COND_AL = 0xE
)

// Decoder ARM64 解码器，实现 vm.Decoder 接口
type Decoder struct{}

// NewDecoder 创建 ARM64 解码器
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode 解码一条 ARM64 指令
func (d *Decoder) Decode(raw uint32, offset int) vm.Instruction {
	inst := vm.Instruction{Raw: raw, Op: int(UNKNOWN), Offset: offset, Rd: -1, Rn: -1, Rm: -1}

	// NOP 快速路径
	if raw == 0xD503201F {
		inst.Op = int(NOP)
		return inst
	}

	op0 := (raw >> 25) & 0xF

	var matched bool
	switch {
	case op0>>1 == 0b100:
		matched = matchAndDecode(raw, dpImmPatterns, &inst)
	case op0>>1 == 0b101:
		matched = matchAndDecode(raw, branchPatterns, &inst)
	case op0&0b0101 == 0b0100:
		matched = matchAndDecode(raw, ldstPatterns, &inst)
	case op0&0b0111 == 0b0101, op0 == 0b1101:
		matched = matchAndDecode(raw, dpRegPatterns, &inst)
	}

	if !matched {
		inst.Op = int(UNSUPPORTED)
	}

	return inst
}

// InstName 返回指令名称
func (d *Decoder) InstName(op int) string {
	return OpName(Op(op))
}

// SignExtend 符号扩展
func SignExtend(val uint32, bits int) int64 {
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int64(int32(val | ^mask))
	}
	return int64(val & mask)
}

// decodeBitmaskImm 解码 ARM64 逻辑立即数的 bitmask 编码
func decodeBitmaskImm(n, immr, imms uint32, is64 bool) (uint64, bool) {
	var regSize uint32 = 32
	if is64 {
		regSize = 64
	}
	var len_ int
	if n != 0 {
		len_ = 6
	} else {
		combined := (^imms) & 0x3F
		for len_ = 5; len_ >= 1; len_-- {
			if combined&(1<<len_) != 0 {
				break
			}
		}
		if len_ < 1 {
			return 0, false
		}
	}
	eSize := uint32(1) << len_
	if eSize > regSize {
		return 0, false
	}
	levels := eSize - 1
	s := imms & levels
	r := immr & levels
	if s == levels {
		return 0, false
	}
	welem := uint64((1 << (s + 1)) - 1)
	if r != 0 {
		welem = (welem >> r) | (welem << (eSize - r))
		welem &= (1 << eSize) - 1
	}
	var result uint64
	for pos := uint32(0); pos < regSize; pos += eSize {
		result |= welem << pos
	}
	return result, true
}

// OpName 指令名称映射
func OpName(op Op) string {
	names := map[Op]string{
		ADD_IMM: "ADD(imm)", SUB_IMM: "SUB(imm)",
		ADDS_IMM: "ADDS(imm)", SUBS_IMM: "SUBS(imm)",
		AND_IMM: "AND(imm)", ORR_IMM: "ORR(imm)", EOR_IMM: "EOR(imm)",
		MOVZ: "MOVZ", MOVK: "MOVK", MOVN: "MOVN",
		UBFM: "UBFM", SBFM: "SBFM",
		ADD_REG: "ADD(reg)", SUB_REG: "SUB(reg)",
		ADDS_REG: "ADDS(reg)", SUBS_REG: "SUBS(reg)",
		AND_REG: "AND(reg)", ORR_REG: "ORR(reg)", EOR_REG: "EOR(reg)",
		EON: "EON", ANDS_REG: "ANDS(reg)",
		LSL_REG: "LSL(reg)", LSR_REG: "LSR(reg)",
		ASR_REG: "ASR(reg)", ROR_REG: "ROR(reg)",
		MUL: "MUL", MADD: "MADD", MSUB: "MSUB", UMULH: "UMULH",
		SMADDL: "SMADDL", SMSUBL: "SMSUBL",
		UMADDL: "UMADDL", UMSUBL: "UMSUBL",
		SDIV: "SDIV", UDIV: "UDIV", MVN: "MVN",
		LDR_IMM: "LDR(imm)", LDRB_IMM: "LDRB(imm)", LDRH_IMM: "LDRH(imm)",
		LDRSB_IMM: "LDRSB(imm)", LDRSH_IMM: "LDRSH(imm)", LDRSW_IMM: "LDRSW(imm)",
		STR_IMM: "STR(imm)", STRB_IMM: "STRB(imm)", STRH_IMM: "STRH(imm)",
		LDR_REG: "LDR(reg)", LDRB_REG: "LDRB(reg)", STRB_REG: "STRB(reg)", STR_REG: "STR(reg)",
		LDRH_REG: "LDRH(reg)", STRH_REG: "STRH(reg)",
		LDRSB_REG: "LDRSB(reg)", LDRSH_REG: "LDRSH(reg)", LDRSW_REG: "LDRSW(reg)",
		LDR_LIT: "LDR(lit)",
		LDP:     "LDP", STP: "STP",
		B: "B", BL: "BL", BR: "BR", BLR: "BLR", RET: "RET",
		B_COND: "B.cond", CBZ: "CBZ", CBNZ: "CBNZ",
		TBZ: "TBZ", TBNZ: "TBNZ",
		CSEL: "CSEL", CSINC: "CSINC", CSINV: "CSINV", CSNEG: "CSNEG",
		ADR: "ADR", ADRP: "ADRP", NOP: "NOP", SVC: "SVC",
		EXTR:    "EXTR",
		LD1_16B: "LD1{16B}", ST1_16B: "ST1{16B}",
		ANDS_IMM: "ANDS(imm)",
		ADD_EXT:  "ADD(ext)", SUB_EXT: "SUB(ext)",
		ADDS_EXT: "ADDS(ext)", SUBS_EXT: "SUBS(ext)",
		CCMP_REG: "CCMP(reg)", CCMP_IMM: "CCMP(imm)",
		CCMN_REG: "CCMN(reg)", CCMN_IMM: "CCMN(imm)",
		MRS: "MRS",
		BIC: "BIC", BICS: "BICS", ORN: "ORN", BFM: "BFM",
		SMULH: "SMULH", CLZ: "CLZ", CLS: "CLS",
		RBIT: "RBIT", REV: "REV", REV16: "REV16", REV32: "REV32",
		ADC: "ADC", ADCS: "ADCS", SBC: "SBC", SBCS: "SBCS",
		DMB: "DMB", DSB: "DSB", ISB: "ISB",
		WFE: "WFE", WFI: "WFI", YIELD_ARM: "YIELD", CLREX: "CLREX",
		HLT: "HLT", BRK: "BRK",
		MSR_WRITE: "MSR", PRFM: "PRFM",
		LDAR: "LDAR", STLR: "STLR", LDAXR: "LDAXR", STLXR: "STLXR",
		LDPSW: "LDPSW", LDADD: "LDADD", CAS: "CAS",
		PACIASP: "PACIASP", AUTIASP: "AUTIASP", PACIAZ: "PACIAZ", AUTIAZ: "AUTIAZ", PACIBSP: "PACIBSP", AUTIBSP: "AUTIBSP", XPACLRI: "XPACLRI",
		BTI_C: "BTI c", BTI_J: "BTI j", BTI_JC: "BTI jc", BTI: "BTI",
	}
	if n, ok := names[op]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%X)", int(op))
}
