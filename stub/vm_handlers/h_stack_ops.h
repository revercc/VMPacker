/*
 * h_stack_ops.h — 栈机器操作 handler
 *
 * 纯栈机器指令集。所有操作数通过 eval_stk[] 操作栈传递，
 * 彻底消除寄存器冲突问题。
 *
 * 栈操作宏:
 *   SPUSH(val): push val 到操作栈
 *   SPOP():     pop 操作栈顶并返回值
 *   SPEEK():    读操作栈顶但不 pop
 */
#ifndef H_STACK_OPS_H
#define H_STACK_OPS_H

#include "../vm_decode.h"
#include "../vm_types.h"

/* ---- 操作栈宏 (带边界检查) ---- */
#define SPUSH(vm, val)                                                         \
  do {                                                                         \
    if (__builtin_expect((vm)->eval_sp < VM_EVAL_STACK_SIZE - 1, 1))           \
      (vm)->eval_stk[++(vm)->eval_sp] = (u64)(val);                            \
  } while (0)
#define SPOP(vm)                                                               \
  (__builtin_expect((vm)->eval_sp >= 0, 1) ? (vm)->eval_stk[(vm)->eval_sp--]   \
                                           : 0)
#define SPEEK(vm)                                                              \
  (__builtin_expect((vm)->eval_sp >= 0, 1) ? (vm)->eval_stk[(vm)->eval_sp] : 0)

/* ================================================================
 * 栈 ↔ 寄存器传输
 * ================================================================ */

/* VLOAD r: push R[r] → 操作栈 */
static inline u32 h_s_vload(vm_ctx_t *vm) {
  u8 r = vm->bc[vm->pc + 1];
  SPUSH(vm, vm->R[r & 31]);
  return 2;
}

/* VSTORE r: pop → R[r] */
static inline u32 h_s_vstore(vm_ctx_t *vm) {
  u8 r = vm->bc[vm->pc + 1];
  vm->R[r & 31] = SPOP(vm);
  return 2;
}

/* PUSH_IMM32: push 32-bit immediate */
static inline u32 h_s_push_imm32(vm_ctx_t *vm) {
  u32 imm = rd32(&vm->bc[vm->pc + 1]);
  SPUSH(vm, (u64)imm);
  return 5;
}

/* PUSH_IMM64: push 64-bit immediate */
static inline u32 h_s_push_imm64(vm_ctx_t *vm) {
  u64 imm = rd64(&vm->bc[vm->pc + 1]);
  SPUSH(vm, imm);
  return 9;
}

/* ================================================================
 * 栈控制
 * ================================================================ */

/* DUP: 复制栈顶 */
static inline u32 h_s_dup(vm_ctx_t *vm) {
  u64 v = SPEEK(vm);
  SPUSH(vm, v);
  return 1;
}

/* SWAP: 交换栈顶两元素 */
static inline u32 h_s_swap(vm_ctx_t *vm) {
  u64 a = SPOP(vm);
  u64 b = SPOP(vm);
  SPUSH(vm, a);
  SPUSH(vm, b);
  return 1;
}

/* DROP: 丢弃栈顶 */
static inline u32 h_s_drop(vm_ctx_t *vm) {
  SPOP(vm);
  return 1;
}

/* ================================================================
 * 栈 ALU — 二元操作: pop b, pop a, push result
 * ================================================================ */

static inline u32 h_s_add(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a + b);
  return 1;
}

static inline u32 h_s_sub(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a - b);
  return 1;
}

static inline u32 h_s_mul(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a * b);
  return 1;
}

static inline u32 h_s_xor(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a ^ b);
  return 1;
}

static inline u32 h_s_and(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a & b);
  return 1;
}

static inline u32 h_s_or(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a | b);
  return 1;
}

static inline u32 h_s_shl(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a << (b & 63));
  return 1;
}

static inline u32 h_s_shr(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, a >> (b & 63));
  return 1;
}

static inline u32 h_s_asr(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, (u64)((i64)a >> (b & 63)));
  return 1;
}

static inline u32 h_s_ror(vm_ctx_t *vm) {
    u64 bits = SPOP(vm);       // 先 pop 位数标记 (32或64)
    u64 shift = SPOP(vm);      // 先 pop 移位量
    u64 val = SPOP(vm);        // 再 pop 要旋转的值
  
    shift &= (bits - 1);
    // val &= 0xFFFFFFFF;
    if (shift == 0) {
        SPUSH(vm, val);
    } else {
        SPUSH(vm, (val >> shift) | (val << (bits - shift)));
    }
    return 1;
}

static inline u32 h_s_umulh(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  __uint128_t r = (__uint128_t)a * (__uint128_t)b;
  SPUSH(vm, (u64)(r >> 64));
  return 1;
}

static inline u32 h_s_smulh(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  __int128 r = (__int128)(i64)a * (__int128)(i64)b;
  SPUSH(vm, (u64)((unsigned __int128)r >> 64));
  return 1;
}

static inline u32 h_s_udiv(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  SPUSH(vm, b == 0 ? 0 : a / b);
  return 1;
}

static inline u32 h_s_sdiv(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  i64 divisor = (i64)b;
  SPUSH(vm, divisor == 0 ? 0 : (u64)((i64)a / divisor));
  return 1;
}

static inline u32 h_s_adc(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  u64 carry = (vm->FL & FL_CARRY) ? 1 : 0;
  SPUSH(vm, a + b + carry);
  return 1;
}

static inline u32 h_s_sbc(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  u64 carry = (vm->FL & FL_CARRY) ? 1 : 0;
  SPUSH(vm, a - b - (1 - carry));
  return 1;
}

/* ================================================================
 * 栈 ALU — 一元操作: pop a, push result
 * ================================================================ */

static inline u32 h_s_not(vm_ctx_t *vm) {
  SPUSH(vm, ~SPOP(vm));
  return 1;
}

static inline u32 h_s_clz(vm_ctx_t *vm) {
  u64 v = SPOP(vm);
  SPUSH(vm, v == 0 ? 64 : (u64)__builtin_clzll(v));
  return 1;
}

static inline u32 h_s_cls(vm_ctx_t *vm) {
  u64 v = SPOP(vm);
  if (v == 0 || v == ~(u64)0) {
    SPUSH(vm, 63);
  } else {
    u64 x = v ^ (v >> 1);
    SPUSH(vm, (u64)__builtin_clzll(x) - 1);
  }
  return 1;
}

static inline u32 h_s_rbit(vm_ctx_t *vm) {
  u64 v = SPOP(vm);
  u64 r = 0;
  for (int i = 0; i < 64; i++) {
    r = (r << 1) | (v & 1);
    v >>= 1;
  }
  SPUSH(vm, r);
  return 1;
}

static inline u32 h_s_rev(vm_ctx_t *vm) {
  SPUSH(vm, __builtin_bswap64(SPOP(vm)));
  return 1;
}

static inline u32 h_s_rev16(vm_ctx_t *vm) {
  u64 v = SPOP(vm);
  u64 r = 0;
  for (int i = 0; i < 4; i++) {
    u16 hw = (u16)(v >> (i * 16));
    hw = (u16)((hw >> 8) | (hw << 8));
    r |= (u64)hw << (i * 16);
  }
  SPUSH(vm, r);
  return 1;
}

static inline u32 h_s_rev32(vm_ctx_t *vm) {
  u64 v = SPOP(vm);
  u32 lo = __builtin_bswap32((u32)v);
  u32 hi = __builtin_bswap32((u32)(v >> 32));
  SPUSH(vm, ((u64)hi << 32) | (u64)lo);
  return 1;
}

static inline u32 h_s_trunc32(vm_ctx_t *vm) {
  SPUSH(vm, SPOP(vm) & 0xFFFFFFFFULL);
  return 1;
}

static inline u32 h_s_sext32(vm_ctx_t *vm) {
  u64 v = SPOP(vm);
  SPUSH(vm, (u64)(i64)(i32)(u32)v);
  return 1;
}

/* ================================================================
 * 栈比较
 * ================================================================ */

/* VCMP: pop b, pop a → set flags(a - b) */
static inline u32 h_s_cmp(vm_ctx_t *vm) {
  u64 b = SPOP(vm), a = SPOP(vm);
  u64 diff = a - b;
  u32 fl = 0;
  if (diff == 0)
    fl |= FL_ZERO;
  if ((i64)a < (i64)b)
    fl |= FL_SIGN;
  if (a < b)
    fl |= FL_CARRY;
  vm->FL = fl;
  return 1;
}

/* ================================================================
 * 栈内存访问
 * ================================================================ */

/* LD8: pop addr → push *(u8*)addr */
static inline u32 h_s_ld8(vm_ctx_t *vm) {
  u64 addr = SPOP(vm);
  SPUSH(vm, *(u8 *)addr);
  return 1;
}

static inline u32 h_s_ld16(vm_ctx_t *vm) {
  u64 addr = SPOP(vm);
  SPUSH(vm, *(u16 *)addr);
  return 1;
}

static inline u32 h_s_ld32(vm_ctx_t *vm) {
  u64 addr = SPOP(vm);
  SPUSH(vm, *(u32 *)addr);
  return 1;
}

static inline u32 h_s_ld64(vm_ctx_t *vm) {
  u64 addr = SPOP(vm);
  SPUSH(vm, *(u64 *)addr);
  return 1;
}

/* ST8: pop val, pop addr → *(u8*)addr = val */
static inline u32 h_s_st8(vm_ctx_t *vm) {
  u64 val = SPOP(vm);
  u64 addr = SPOP(vm);
  *(u8 *)addr = (u8)val;
  return 1;
}

static inline u32 h_s_st16(vm_ctx_t *vm) {
  u64 val = SPOP(vm);
  u64 addr = SPOP(vm);
  *(u16 *)addr = (u16)val;
  return 1;
}

static inline u32 h_s_st32(vm_ctx_t *vm) {
  u64 val = SPOP(vm);
  u64 addr = SPOP(vm);
  *(u32 *)addr = (u32)val;
  return 1;
}

static inline u32 h_s_st64(vm_ctx_t *vm) {
  u64 val = SPOP(vm);
  u64 addr = SPOP(vm);
  *(u64 *)addr = val;
  return 1;
}

#endif /* H_STACK_OPS_H */
