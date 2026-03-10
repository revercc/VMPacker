package arm64

import (
	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// 特殊指令翻译 — ADRP / ADR
// ============================================================

func (t *Translator) trADRP(instructions []vm.Instruction, idx int) (int, error) {
	inst := instructions[idx]
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return 0, err
	}

	pc := t.funcAddr + uint64(inst.Offset)
	pageBase := pc &^ 0xFFF
	adrpResult := pageBase + uint64(inst.Imm)
	fixPos := t.pos()

	if idx+1 < len(instructions) {
		next := instructions[idx+1]
		if Op(next.Op) == ADD_IMM && next.Rd == inst.Rd && next.Rn == inst.Rd {
			finalAddr := adrpResult + uint64(next.Imm)
			t.emit(vm.OpMovImm, rd)
			t.emitU64(0)
			// 记录重定位信息
			reloc := Relocation{
				BcOffset:   uint64(fixPos),
				TargetAddr: finalAddr,
				IsInternal: true,
				FuncName:   t.currentFuncName,
			}
			t.relocations = append(t.relocations, reloc)
			return 1, nil
		}
	}

	t.emit(vm.OpMovImm, rd)
	t.emitU64(0)
	// 记录重定位信息
	reloc := Relocation{
		BcOffset:   uint64(fixPos),
		TargetAddr: adrpResult,
		IsInternal: true,
		FuncName:   t.currentFuncName,
	}
	t.relocations = append(t.relocations, reloc)
	return 0, nil
}

func (t *Translator) trADR(inst vm.Instruction) (int, error) {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return 0, err
	}
	pc := t.funcAddr + uint64(inst.Offset)
	addr := pc + uint64(inst.Imm)
	fixPos := t.pos()
	t.emit(vm.OpMovImm, rd)
	t.emitU64(0)

	// 记录重定位信息
	reloc := Relocation{
		BcOffset:   uint64(fixPos),
		TargetAddr: addr,
		IsInternal: true,
		FuncName:   t.currentFuncName,
	}
	t.relocations = append(t.relocations, reloc)
	return 0, nil
}

// trSVC 翻译 SVC #imm16
// 字节码: [OpSvc][imm16_lo][imm16_hi] = 3B
// handler 使用 inline asm 执行 svc #0，从 VM 寄存器传递 syscall 参数
func (t *Translator) trSVC(inst vm.Instruction) error {
	imm16 := uint16(inst.Imm)
	t.emit(vm.OpSvc, byte(imm16), byte(imm16>>8))
	return nil
}
