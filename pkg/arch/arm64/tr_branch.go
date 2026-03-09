package arm64

import (
	"fmt"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// 分支翻译 — B / B.cond / BL / BLR / BR / TBZ
// CSEL/CBZ 已迁移到 tr_stack.go (trStackCSEL/trStackCBZ)
// ============================================================

func (t *Translator) trBranch(inst vm.Instruction) error {
	target := inst.Offset + int(inst.Imm)

	if target < 0 || target > t.funcSize {
		return fmt.Errorf("分支目标 0x%X 超出函数范围 [0, 0x%X)", target, t.funcSize)
	}

	t.emit(vm.OpJmp)
	fixPos := t.pos()
	t.emitU32(0)
	t.fixups = append(t.fixups, branchFixup{vmOffset: fixPos, arm64Target: target})
	return nil
}

func (t *Translator) trBranchCond(inst vm.Instruction) error {
	target := inst.Offset + int(inst.Imm)

	if target < 0 || target > t.funcSize {
		return fmt.Errorf("条件分支目标 0x%X 超出函数范围 [0, 0x%X]", target, t.funcSize)
	}

	var vmOp byte
	switch inst.Cond {
	case COND_EQ:
		vmOp = vm.OpJe
	case COND_NE:
		vmOp = vm.OpJne
	case COND_LT:
		vmOp = vm.OpJl
	case COND_GE:
		vmOp = vm.OpJge
	case COND_GT:
		vmOp = vm.OpJgt
	case COND_LE:
		vmOp = vm.OpJle
	case COND_CS:
		vmOp = vm.OpJae
	case COND_CC:
		vmOp = vm.OpJb
	case COND_HI:
		vmOp = vm.OpJa
	case COND_LS:
		vmOp = vm.OpJbe
	case COND_MI:
		vmOp = vm.OpJl // MI: N==1 → FL_SIGN set
	case COND_PL:
		vmOp = vm.OpJge // PL: N==0 → FL_SIGN not set
	default:
		return fmt.Errorf("不支持的条件码 0x%X", inst.Cond)
	}

	t.emit(vmOp)
	fixPos := t.pos()
	t.emitU32(0)
	t.fixups = append(t.fixups, branchFixup{vmOffset: fixPos, arm64Target: target})
	return nil
}

func (t *Translator) trBL(inst vm.Instruction) error {
	target := uint64(int64(t.funcAddr) + int64(inst.Offset) + inst.Imm)
	off := t.pos()
	t.emit(vm.OpMovImm, 15)
	t.emitU64(0)
	t.emit(vm.OpCallReg, 15)

	reloc := Relocation{
		BcOffset:   uint64(off),
		TargetAddr: target,
		IsInternal: true, // 同一个 .so 内
		FuncName:   t.currentFuncName,
	}
	t.relocations = append(t.relocations, reloc)
	return nil
}

func (t *Translator) trBLR(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	t.emit(vm.OpCallReg, rn)
	return nil
}

func (t *Translator) trBR(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	t.emit(vm.OpBrReg, rn)
	return nil
}

// trTBZ 翻译 TBZ/TBNZ — test bit and branch
// 字节码: [OpTbz/OpTbnz][reg][bit][target32] = 7B
// inst.Shift = bit number (b5:b40), inst.Imm = offset (已乘4)
func (t *Translator) trTBZ(inst vm.Instruction, isZero bool) error {
	target := inst.Offset + int(inst.Imm)

	if target < 0 || target > t.funcSize {
		return fmt.Errorf("TBZ/TBNZ 分支目标 0x%X 超出函数范围 [0, 0x%X)", target, t.funcSize)
	}

	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}

	var vmOp byte
	if isZero {
		vmOp = vm.OpTbz
	} else {
		vmOp = vm.OpTbnz
	}

	t.emit(vmOp, rd, byte(inst.Shift))
	fixPos := t.pos()
	t.emitU32(0)
	t.fixups = append(t.fixups, branchFixup{vmOffset: fixPos, arm64Target: target})
	return nil
}
