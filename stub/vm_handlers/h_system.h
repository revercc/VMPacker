/*
 * h_system.h — 系统/特殊指令 handler
 *
 * NOP / HALT / RET / CALL_NAT / VLD16 / VST16
 */
#ifndef H_SYSTEM_H
#define H_SYSTEM_H

#include "../vm_decode.h"
#include "../vm_types.h"

/* NOP  [1B] */
static inline u32 h_nop(vm_ctx_t *vm) {
  (void)vm;
  return 1;
}

/* CALL_NAT: BLR 绝对地址调用  [9B: op | addr64] */
static inline u32 h_call_nat(vm_ctx_t *vm) {
  u64 addr = rd64(&vm->bc[vm->pc + 1]);
  native_fn_t fn = (native_fn_t)addr;
  vm->R[0] = fn(vm->R[0], vm->R[1], vm->R[2], vm->R[3], vm->R[4], vm->R[5],
                vm->R[6], vm->R[7]);
  return 9;
}

/* CALL_REG: BLR Xn (寄存器间接调用) [2B: op | rn] */
static inline u32 h_call_reg(vm_ctx_t *vm) {
  u8 rn = vm->bc[vm->pc + 1];
  u64 addr = vm->R[rn & 31];
  native_fn_t fn = (native_fn_t)addr;
  vm->R[0] = fn(vm->R[0], vm->R[1], vm->R[2], vm->R[3], vm->R[4], vm->R[5],
                vm->R[6], vm->R[7]);
  return 2;
}

/* BR_REG: BR Xn (寄存器间接跳转) [2B: op | rn]
 * 两种情况:
 *   1) 目标在被保护函数内 → computed goto, 查映射表做 VM 内部跳转
 *   2) 目标在函数外 → 尾调用, 当 native call 处理
 * 返回 0 表示已直接设置 vm->pc (内部跳转) */
static inline u32 h_br_reg(vm_ctx_t *vm) {
  u8 rn = vm->bc[vm->pc + 1];
  u64 addr = vm->R[rn & 31];

  /* 检查目标是否在被保护函数的地址范围内 */
  if (vm->map_count > 0 && addr >= vm->func_addr &&
      addr < vm->func_addr + vm->func_size) {
    u32 arm64_off = (u32)(addr - vm->func_addr);
    /* 二分查找 (addr_map 已按 arm64_off 升序排序) */
    u32 lo = 0, hi = vm->map_count;
    while (lo < hi) {
      u32 mid = lo + ((hi - lo) >> 1);
      u32 mid_off = vm->addr_map[mid].arm64_off;
      if (mid_off < arm64_off)
        lo = mid + 1;
      else if (mid_off > arm64_off)
        hi = mid;
      else {
        vm->pc = vm->addr_map[mid].vm_off;
        return 0; /* 已设置 pc, 不再 advance */
      }
    }
    /* 未找到映射 */
    return 2; /* skip, 继续 */
  }

  /* 外部尾调用 → native call */
  native_fn_t fn = (native_fn_t)addr;
  vm->R[0] = fn(vm->R[0], vm->R[1], vm->R[2], vm->R[3], vm->R[4], vm->R[5],
                vm->R[6], vm->R[7]);
  return 2;
}

/* VLD16: LD1 {Vn.16B}, [Xn]  [3B: op | rn | len] */
static inline u32 h_vld16(vm_ctx_t *vm) {
  u8 rn = vm->bc[vm->pc + 1];
  u8 len = vm->bc[vm->pc + 2];
  const u8 *src = (const u8 *)vm->R[rn & 31];
  for (int i = 0; i < len && i < VM_SIMD_BUF; i++)
    vm->vtmp[i] = src[i];
  return 3;
}

/* VST16: ST1 {Vn.16B}, [Xn]  [3B: op | rn | len] */
static inline u32 h_vst16(vm_ctx_t *vm) {
  u8 rn = vm->bc[vm->pc + 1];
  u8 len = vm->bc[vm->pc + 2];
  u8 *dst = (u8 *)vm->R[rn & 31];
  for (int i = 0; i < len && i < VM_SIMD_BUF; i++)
    dst[i] = vm->vtmp[i];
  return 3;
}

/* SVC #imm16  [3B: op | imm16_lo | imm16_hi]
 * 执行 Linux syscall: X8=syscall号, X0-X5=参数, 结果写回 X0
 * imm16 通常为 0 (Linux AArch64 只用 svc #0) */
static inline u32 h_svc(vm_ctx_t *vm) {
  /* 从 VM 寄存器读取 syscall 参数 */
  register long x8 __asm__("x8") = (long)vm->R[8]; /* syscall number */
  register long x0 __asm__("x0") = (long)vm->R[0];
  register long x1 __asm__("x1") = (long)vm->R[1];
  register long x2 __asm__("x2") = (long)vm->R[2];
  register long x3 __asm__("x3") = (long)vm->R[3];
  register long x4 __asm__("x4") = (long)vm->R[4];
  register long x5 __asm__("x5") = (long)vm->R[5];
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory");
  vm->R[0] = (u64)x0;
  return 3;
}

/* MRS Xd, <sysreg>  [4B: op | d | sysreg_lo | sysreg_hi]
 * 读取 ARM64 系统寄存器到 VM 虚拟寄存器。
 * sysreg 是 15-bit 编码 = bits[19:5] of the MRS instruction.
 * 支持的系统寄存器:
 *   0x5F02 = cntvct_el0 (timer count)
 *   0x5F00 = cntfrq_el0 (timer frequency)
 *   0x5E82 = TPIDR_EL0   (Software Thread ID)
 *   0x5E83 = TPIDRRO_EL0 (Read-only Software Thread ID)
 *   0x5A10 = NZCV        (标志位寄存器)
 */
static inline u32 h_mrs(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1];
  u16 sysreg = (u16)vm->bc[vm->pc + 2] | ((u16)vm->bc[vm->pc + 3] << 8);
  u64 val = 0;
  switch (sysreg) {
  case 0x5F02: /* cntvct_el0 */
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    break;
  case 0x5F00: /* cntfrq_el0 */
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(val));
    break;
  case 0x5E82: /* TPIDR_EL0 - Software Thread ID */
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(val));
    break;  
  case 0x5E83: /* TPIDRRO_EL0 - Read-only Software Thread ID */
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(val));
    break;
  case 0x5A10: /* NZCV - 标志位寄存器 */
      val = ((vm->FL & FL_ZERO) ? 0x4 : 0)   /* Z bit (bit 2) */
          | ((vm->FL & FL_SIGN) ? 0x8 : 0)   /* N bit (bit 3) */
          | (!(vm->FL & FL_CARRY) ? 0x2 : 0); /* C bit (bit 1), 注意: 我们的 FL_CARRY = 无符号小于, ARM C 是反向的 */
      val = val << 28; /* NZCV 在高 4 位 */
    break;
  default:
    /* 不支持的系统寄存器，返回 0 */
    break;
  }
  vm->R[d & 31] = val;
  return 4;
}

#endif /* H_SYSTEM_H */
