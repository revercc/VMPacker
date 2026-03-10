package arm64

import "github.com/vmpacker/pkg/vm"

// ============================================================
// 分支 / 异常 / 系统 模式表
//
// 覆盖: B/BL, BR/BLR/RET, B.cond, CBZ/CBNZ, TBZ/TBNZ, SVC
// ============================================================

var branchPatterns = []InstrPattern{
	// ---- Conditional branch (B.cond) ----
	// 编码: 0101010:0:imm19:0:cond
	{
		Name: "B_COND", Mask: 0xFF000010, Value: 0x54000000, Op: B_COND,
		Fields: []FieldDef{
			{Name: "imm19", Hi: 23, Lo: 5, Signed: true},
			{Name: "cond", Hi: 3, Lo: 0},
		},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm19"] * 4
		},
	},

	// ---- Compare and branch (CBZ/CBNZ) ----
	// 编码: sf:011010:op:imm19:Rt
	{
		Name: "CBZ", Mask: 0x7F000000, Value: 0x34000000, Op: CBZ,
		Fields: []FieldDef{fSF, {Name: "imm19", Hi: 23, Lo: 5, Signed: true}, fRd},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm19"] * 4
		},
	},
	{
		Name: "CBNZ", Mask: 0x7F000000, Value: 0x35000000, Op: CBNZ,
		Fields: []FieldDef{fSF, {Name: "imm19", Hi: 23, Lo: 5, Signed: true}, fRd},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm19"] * 4
		},
	},

	// ---- Test and branch (TBZ/TBNZ) ----
	// 编码: b5:011011:op:b40:imm14:Rt
	{
		Name: "TBZ", Mask: 0x7F000000, Value: 0x36000000, Op: TBZ,
		Fields: []FieldDef{
			{Name: "b5", Hi: 31, Lo: 31},
			{Name: "b40", Hi: 23, Lo: 19},
			{Name: "imm14", Hi: 18, Lo: 5, Signed: true},
			fRd,
		},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm14"] * 4
			inst.Shift = int((f["b5"] << 5) | f["b40"])
		},
	},
	{
		Name: "TBNZ", Mask: 0x7F000000, Value: 0x37000000, Op: TBNZ,
		Fields: []FieldDef{
			{Name: "b5", Hi: 31, Lo: 31},
			{Name: "b40", Hi: 23, Lo: 19},
			{Name: "imm14", Hi: 18, Lo: 5, Signed: true},
			fRd,
		},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm14"] * 4
			inst.Shift = int((f["b5"] << 5) | f["b40"])
		},
	},

	// ---- Unconditional branch (B/BL) ----
	// 编码: op:00101:imm26
	{
		Name: "B", Mask: 0xFC000000, Value: 0x14000000, Op: B,
		Fields: []FieldDef{{Name: "imm26", Hi: 25, Lo: 0, Signed: true}},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm26"] * 4
		},
	},
	{
		Name: "BL", Mask: 0xFC000000, Value: 0x94000000, Op: BL,
		Fields: []FieldDef{{Name: "imm26", Hi: 25, Lo: 0, Signed: true}},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm26"] * 4
		},
	},

	// ---- Unconditional branch (register): BR/BLR/RET ----
	// 编码: 1101011:0:opc:11111:000000:Rn:00000
	{
		Name: "BR", Mask: 0xFFFFFC1F, Value: 0xD61F0000, Op: BR,
		Fields: []FieldDef{fRn},
	},
	{
		Name: "BLR", Mask: 0xFFFFFC1F, Value: 0xD63F0000, Op: BLR,
		Fields: []FieldDef{fRn},
	},
	{
		Name: "RET", Mask: 0xFFFFFC1F, Value: 0xD65F0000, Op: RET,
		Fields: []FieldDef{fRn},
	},

	// ---- Supervisor Call ----
	// 编码: 11010100_000:imm16:00000
	{
		Name: "SVC", Mask: 0xFFE0001F, Value: 0xD4000001, Op: SVC,
		Fields: []FieldDef{{Name: "imm16", Hi: 20, Lo: 5}},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["imm16"]
		},
	},

	// ---- MRS (system register read) ----
	// 编码: 1101010100:1:1:op0:op1:CRn:CRm:op2:Rt
	// Mask: 0xFFF00000 = 0xD5300000 只匹配 MRS（不匹配 MSR）
	// sysreg 编码: bits[20:5] = op0:op1:CRn:CRm:op2 (15位)
	{
		Name: "MRS", Mask: 0xFFF00000, Value: 0xD5300000, Op: MRS,
		Fields: []FieldDef{
			fRd,
			{Name: "sysreg", Hi: 19, Lo: 5},
		},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["sysreg"]
			inst.SF = true // MRS always 64-bit
		},
	},

	// ---- MSR (system register write) ----
	// 编码: 1101010100:0:1:op0:op1:CRn:CRm:op2:Rt
	{
		Name: "MSR", Mask: 0xFFF00000, Value: 0xD5100000, Op: MSR_WRITE,
		Fields: []FieldDef{
			fRd, // Rt (source register)
			{Name: "sysreg", Hi: 19, Lo: 5},
		},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = f["sysreg"]
			inst.SF = true
		},
	},

	// ---- Barriers: DMB/DSB/ISB ----
	// 编码: 1101_0101_0000_0011_0011_CRm_op2_11111
	{Name: "DMB", Mask: 0xFFFFF0FF, Value: 0xD50330BF, Op: DMB},
	{Name: "DSB", Mask: 0xFFFFF0FF, Value: 0xD503309F, Op: DSB},
	{Name: "ISB", Mask: 0xFFFFF0FF, Value: 0xD50330DF, Op: ISB},

	// ---- Hints: YIELD/WFE/WFI ----
	{Name: "YIELD", Mask: 0xFFFFFFFF, Value: 0xD503203F, Op: YIELD_ARM},
	{Name: "WFE", Mask: 0xFFFFFFFF, Value: 0xD503205F, Op: WFE},
	{Name: "WFI", Mask: 0xFFFFFFFF, Value: 0xD503207F, Op: WFI},

	// ---- CLREX ----
	{Name: "CLREX", Mask: 0xFFFFF0FF, Value: 0xD503305F, Op: CLREX},

	// ---- Exception generation: HLT/BRK ----
	{Name: "HLT", Mask: 0xFFE0001F, Value: 0xD4400000, Op: HLT},
	{Name: "BRK", Mask: 0xFFE0001F, Value: 0xD4200000, Op: BRK},

	// ---- PACIASP - 对 LR 使用 SP 作为修饰符进行签名 ----
	// 编码: 1101_0101_0000_0011_0010_0011_1111_1111
	// 实际上这是 HINT #32 的特殊形式
	{
		Name:   "PACIASP",
		Mask:   0xFFFFFFFF,
		Value:  0xD503237F, // HINT #32, 在支持 PAC 的 CPU 上是 PACIASP
		Op:     PACIASP,
		Fields: []FieldDef{}, // 无字段
		Post: func(f map[string]int64, inst *vm.Instruction) {
			// PACIASP 不涉及立即数或寄存器操作数
			inst.Imm = 0
		},
	},

	// ---- AUTIASP - 验证并还原 LR ----
	// 编码: 1101_0101_0000_0011_0010_0011_1011_1111
	{
		Name:   "AUTIASP",
		Mask:   0xFFFFFFFF,
		Value:  0xD50323BF, // HINT #46, 在支持 PAC 的 CPU 上是 AUTIASP
		Op:     AUTIASP,
		Fields: []FieldDef{},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = 0
		},
	},

	// ---- PACIAZ - 使用零作为修饰符对 LR 签名 ----
	{
		Name:  "PACIAZ",
		Mask:  0xFFFFFFFF,
		Value: 0xD503233F, // HINT #38
		Op:    PACIAZ,
	},

	// ---- AUTIAZ - 使用零作为修饰符验证 LR ----
	{
		Name:  "AUTIAZ",
		Mask:  0xFFFFFFFF,
		Value: 0xD50323FF, // HINT #63
		Op:    AUTIAZ,
	},

	// ---- PACIBSP - 使用 SP 作为修饰符对 LR 签名 (使用 B 密钥) ----
	{
		Name:  "PACIBSP",
		Mask:  0xFFFFFFFF,
		Value: 0xD50327FF, // HINT #31 的某种形式
		Op:    PACIBSP,
	},

	// ---- AUTIBSP - 使用 SP 作为修饰符验证 LR (使用 B 密钥) ----
	{
		Name:  "AUTIBSP",
		Mask:  0xFFFFFFFF,
		Value: 0xD50327BF, // HINT #47
		Op:    AUTIBSP,
	},

	// ---- XPACLRI - 清除 PAC 签名 ----
	{
		Name:  "XPACLRI",
		Mask:  0xFFFFFFFF,
		Value: 0xD50320FF, // HINT #7
		Op:    XPACLRI,
	},

	// BTI (Branch Target Identification) 指令
	// ---- BTI C - 接受 CALL 类型跳转 ----
	{
		Name:   "BTI C",
		Mask:   0xFFFFFFFF,
		Value:  0xD503245F, // HINT #36
		Op:     BTI_C,
		Fields: []FieldDef{},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = 36 // hint number
		},
	},

	// ---- BTI J - 接受 JUMP 类型跳转 ----
	{
		Name:   "BTI J",
		Mask:   0xFFFFFFFF,
		Value:  0xD503255F, // HINT #44
		Op:     BTI_J,
		Fields: []FieldDef{},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = 44
		},
	},

	// ---- BTI JC - 接受两者 ----
	{
		Name:   "BTI JC",
		Mask:   0xFFFFFFFF,
		Value:  0xD503265F, // HINT #50
		Op:     BTI_JC,
		Fields: []FieldDef{},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = 50
		},
	},

	// ---- BTI (默认 = BTI JC) ----
	{
		Name:   "BTI",
		Mask:   0xFFFFFFFF,
		Value:  0xD503275F, // HINT #62
		Op:     BTI,
		Fields: []FieldDef{},
		Post: func(f map[string]int64, inst *vm.Instruction) {
			inst.Imm = 62
		},
	},
}
