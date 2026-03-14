/*
 * vm_decode.h — 字节码读取工具函数
 *
 * 小端读取: 从字节码流中读取 16/32/64 位值。
 */
#ifndef VM_DECODE_H
#define VM_DECODE_H

#include "vm_types.h"

static inline u16 rd16(const u8 *p) { return (u16)p[0] | ((u16)p[1] << 8); }

static inline u32 rd32(const u8 *p) {
  return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline u64 rd64(const u8 *p) {
  return (u64)rd32(p) | ((u64)rd32(p + 4) << 32);
}

/* ---- 指令大小查找 (用于越界保护) ---- */
/* 返回解密后 opcode 对应的指令字节数, 0 = 未知 */
#include "vm_opcodes.h"
static inline u8 vm_insn_size(u8 op) {
  switch (op) {
  case OP_NOP:
  case OP_HALT:
    return 1;
  case OP_RET:
  case OP_PUSH:
  case OP_POP:
  case OP_CALL_REG:
  case OP_BR_REG:
    return 2;
  case OP_MOV_REG:
  case OP_NOT:
  case OP_CMP:
  case OP_VLD16:
  case OP_VST16:
  case OP_SVC:
  case OP_CLZ:
  case OP_CLS:
  case OP_RBIT:
  case OP_REV:
  case OP_REV16:
  case OP_REV32:
    return 3;
  case OP_ADD:
  case OP_SUB:
  case OP_MUL:
  case OP_XOR:
  case OP_AND:
  case OP_OR:
  case OP_SHL:
  case OP_SHR:
  case OP_ASR:
  case OP_ROR:
  case OP_UMULH:
  case OP_UDIV:
  case OP_SDIV:
  case OP_MRS:
  case OP_SMULH:
  case OP_ADC:
  case OP_SBC:
    return 4;
  case OP_LOAD8:
  case OP_LOAD16:
  case OP_LOAD32:
  case OP_LOAD64:
  case OP_STORE8:
  case OP_STORE16:
  case OP_STORE32:
  case OP_STORE64:
  case OP_JMP:
  case OP_JE:
  case OP_JNE:
  case OP_JL:
  case OP_JGE:
  case OP_JGT:
  case OP_JLE:
  case OP_JB:
  case OP_JAE:
  case OP_JBE:
  case OP_JA:
    return 5;
  case OP_MOV_IMM32:
  case OP_CMP_IMM:
  case OP_CCMP_REG:
  case OP_CCMP_IMM:
  case OP_CCMN_REG:
  case OP_CCMN_IMM:
    return 6;
  case OP_ADD_IMM:
  case OP_SUB_IMM:
  case OP_XOR_IMM:
  case OP_AND_IMM:
  case OP_OR_IMM:
  case OP_MUL_IMM:
  case OP_SHL_IMM:
  case OP_SHR_IMM:
  case OP_ASR_IMM:
  case OP_TBZ:
  case OP_TBNZ:
    return 7;
  case OP_CALL_NAT:
    return 9;
  case OP_MOV_IMM:
    return 10;
  /* ---- 栈机器操作码 ---- */
  case OP_S_DUP:
  case OP_S_SWAP:
  case OP_S_DROP:
  case OP_S_ADD:
  case OP_S_SUB:
  case OP_S_MUL:
  case OP_S_XOR:
  case OP_S_AND:
  case OP_S_OR:
  case OP_S_SHL:
  case OP_S_SHR:
  case OP_S_ASR:
  case OP_S_ROR:
  case OP_S_UMULH:
  case OP_S_SMULH:
  case OP_S_UDIV:
  case OP_S_SDIV:
  case OP_S_ADC:
  case OP_S_SBC:
  case OP_S_NOT:
  case OP_S_CLZ:
  case OP_S_CLS:
  case OP_S_RBIT:
  case OP_S_REV:
  case OP_S_REV16:
  case OP_S_REV32:
  case OP_S_TRUNC32:
  case OP_S_SEXT32:
  case OP_S_CMP:
  case OP_S_LD8:
  case OP_S_LD16:
  case OP_S_LD32:
  case OP_S_LD64:
  case OP_S_ST8:
  case OP_S_ST16:
  case OP_S_ST32:
  case OP_S_ST64:
  case OP_S_AD_SETFLAGS:
  case OP_S_SU_SETFLAGS:
    return 1;
  case OP_S_VLOAD:
  case OP_S_VSTORE:
    return 2;
  case OP_S_PUSH_IMM32:
    return 5;
  case OP_S_PUSH_IMM64:
    return 9;
  default:
    return 0;
  }
}

#endif /* VM_DECODE_H */
