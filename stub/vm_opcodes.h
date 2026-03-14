/*
 * vm_opcodes.h — VM 操作码定义
 *
 * 与翻译器 opcodes.go 一一对应。
 * 注释格式: ARM64助记 | 字节码长度 | 编码格式
 */
#ifndef VM_OPCODES_H
#define VM_OPCODES_H

/* ---- 系统 ---- */
#define OP_NOP 0xC3  /* NOP                          1B */
#define OP_HALT 0x00 /* HALT (返回 R[0])             1B */
#define OP_RET 0xEE  /* RET Xn                       2B: [op][n] */

/* ---- 数据移动 (MOV) ---- */
#define OP_MOV_IMM 0x5A /* MOV Xd, #imm64              10B: [op][d][imm64] */
#define OP_MOV_IMM32                                                           \
  0x49                  /* MOV Wd, #imm32               6B: [op][d][imm32]     \
                         */
#define OP_MOV_REG 0x2F /* MOV Xd, Xn                   3B: [op][d][n] */

/* ---- 内存 (LDR/STR) ---- */
#define OP_LOAD8 0x91  /* LDRB Xd, [Xn, #off16]        5B: [op][d][n][off16] */
#define OP_LOAD32 0xA4 /* LDR  Wd, [Xn, #off16]        5B */
#define OP_LOAD64 0xB7 /* LDR  Xd, [Xn, #off16]        5B */
#define OP_STORE8                                                              \
  0xD2                  /* STRB Xn, [Xb, #off16]        5B: [op][b][n][off16]  \
                         */
#define OP_STORE32 0x19 /* STR  Wn, [Xb, #off16]        5B */
#define OP_STORE64 0x2A /* STR  Xn, [Xb, #off16]        5B */
#define OP_LOAD16 0xE7  /* LDRH Xd, [Xn, #off16]        5B */
#define OP_STORE16 0xE8 /* STRH Xn, [Xb, #off16]        5B */

/* ---- 算术/逻辑 (三寄存器) ---- */
#define OP_ADD 0x37   /* ADD  Xd, Xn, Xm              4B: [op][d][n][m] */
#define OP_SUB 0x6E   /* SUB  Xd, Xn, Xm              4B */
#define OP_MUL 0x83   /* MUL  Xd, Xn, Xm              4B */
#define OP_XOR 0x1B   /* EOR  Xd, Xn, Xm              4B */
#define OP_AND 0x4D   /* AND  Xd, Xn, Xm              4B */
#define OP_OR 0x72    /* ORR  Xd, Xn, Xm              4B */
#define OP_SHL 0xAE   /* LSL  Xd, Xn, Xm              4B */
#define OP_SHR 0xF1   /* LSR  Xd, Xn, Xm              4B */
#define OP_ASR 0xDA   /* ASR  Xd, Xn, Xm              4B */
#define OP_UMULH 0xF2 /* UMULH Xd, Xn, Xm            4B */
#define OP_NOT 0x08   /* MVN  Xd, Xn                   3B: [op][d][n] */
#define OP_ROR 0x3D   /* ROR  Xd, Xn, Xm              4B */

/* ---- 算术/逻辑 (寄存器 + 立即数) ---- */
#define OP_ADD_IMM                                                             \
  0xE5                  /* ADD  Xd, Xn, #imm32          7B: [op][d][n][imm32]  \
                         */
#define OP_SUB_IMM 0x78 /* SUB  Xd, Xn, #imm32          7B */
#define OP_XOR_IMM 0x3C /* EOR  Xd, Xn, #imm32          7B */
#define OP_AND_IMM 0xD9 /* AND  Xd, Xn, #imm32          7B */
#define OP_OR_IMM 0x6B  /* ORR  Xd, Xn, #imm32          7B */
#define OP_MUL_IMM 0xB3 /* MUL  Xd, Xn, #imm32          7B */
#define OP_SHL_IMM 0x7A /* LSL  Xd, Xn, #imm32          7B */
#define OP_SHR_IMM 0x8C /* LSR  Xd, Xn, #imm32          7B */
#define OP_ASR_IMM 0x9D /* ASR  Xd, Xn, #imm32          7B */

/* ---- 比较 ---- */
#define OP_CMP 0x9F     /* CMP  Xn, Xm (= SUBS XZR)    3B: [op][n][m] */
#define OP_CMP_IMM 0xA1 /* CMP  Xn, #imm32              6B: [op][n][imm32] */

/* ---- 分支 ---- */
#define OP_JMP 0x44 /* B    target                   5B: [op][target32] */
#define OP_JE 0x58  /* B.EQ (ZF=1)                   5B */
#define OP_JNE 0xBB /* B.NE (ZF=0)                   5B */
#define OP_JL 0x15  /* B.LT (SF=1)                   5B */
#define OP_JGE 0x29 /* B.GE (SF=0)                   5B */
#define OP_JGT 0x36 /* B.GT (!ZF && !SF)             5B */
#define OP_JLE 0x47 /* B.LE (ZF || SF)               5B */
#define OP_JB 0x52  /* B.CC (CF=1, unsigned <)       5B */
#define OP_JAE 0x64 /* B.CS (CF=0, unsigned >=)      5B */
#define OP_JBE 0x53 /* B.LS (CF||ZF, unsigned <=)    5B */
#define OP_JA 0x65  /* B.HI (!CF&&!ZF, unsigned >)   5B */

/* ---- 栈操作 ---- */
#define OP_PUSH 0x63 /* STR  Xn, [SP, #-8]!           2B: [op][n] */
#define OP_POP 0x27  /* LDR  Xn, [SP], #8             2B: [op][n] */

/* ---- 原生调用 ---- */
#define OP_CALL_NAT 0xAB /* BLR  imm64 (绝对地址)        9B: [op][imm64] */
#define OP_CALL_REG 0xBC /* BLR  Xn   (寄存器间接调用)   2B: [op][rn] */
#define OP_BR_REG 0xCD   /* BR   Xn   (寄存器间接跳转)   2B: [op][rn] */

/* ---- SIMD ---- */
#define OP_VLD16 0xC1 /* LD1 {Vn.16B}, [Xn]            3B: [op][rn][len] */
#define OP_VST16 0xC2 /* ST1 {Vn.16B}, [Xn]            3B: [op][rn][len] */

/* ---- TBZ/TBNZ ---- */
#define OP_TBZ                                                                 \
  0x16 /* TBZ  Xt, #bit, target          7B: [op][reg][bit][target32] */
#define OP_TBNZ                                                                \
  0x17 /* TBNZ Xt, #bit, target          7B: [op][reg][bit][target32] */

/* ---- CCMP/CCMN ---- */
#define OP_CCMP_REG                                                            \
  0x18 /* CCMP Xn, Xm, #nzcv, cond   6B: [op][cond][nzcv][rn][rm][sf] */
#define OP_CCMP_IMM                                                            \
  0x1A /* CCMP Xn, #imm5, #nzcv, cond 6B: [op][cond][nzcv][rn][imm5][sf] */
#define OP_CCMN_REG                                                            \
  0x1C /* CCMN Xn, Xm, #nzcv, cond   6B: [op][cond][nzcv][rn][rm][sf] */
#define OP_CCMN_IMM                                                            \
  0x1D /* CCMN Xn, #imm5, #nzcv, cond 6B: [op][cond][nzcv][rn][imm5][sf] */

/* ---- SVC ---- */
#define OP_SVC 0x1E /* SVC #imm16                      3B: [op][imm16_le] */

/* ---- UDIV/SDIV ---- */
#define OP_UDIV 0x1F /* UDIV Xd, Xn, Xm                4B: [op][d][n][m] */
#define OP_SDIV 0x21 /* SDIV Xd, Xn, Xm                4B: [op][d][n][m] */

/* ---- MRS ---- */
#define OP_MRS                                                                 \
  0x20 /* MRS Xd, <sysreg>               4B: [op][d][sysreg_lo][sysreg_hi] */

/* ---- SMULH/CLZ/CLS/RBIT/REV ---- */
#define OP_SMULH 0x22 /* SMULH Xd, Xn, Xm            4B: [op][d][n][m] */
#define OP_CLZ 0x23   /* CLZ   Xd, Xn                3B: [op][d][n] */
#define OP_CLS 0x24   /* CLS   Xd, Xn                3B: [op][d][n] */
#define OP_RBIT 0x25  /* RBIT  Xd, Xn                3B: [op][d][n] */
#define OP_REV 0x26   /* REV   Xd, Xn                3B: [op][d][n] */
#define OP_REV16 0x28 /* REV16 Xd, Xn                3B: [op][d][n] */
#define OP_REV32 0x2B /* REV32 Xd, Xn                3B: [op][d][n] */

/* ---- ADC/SBC ---- */
#define OP_ADC 0x2C /* ADC Xd, Xn, Xm              4B: [op][d][n][m] */
#define OP_SBC 0x2D /* SBC Xd, Xn, Xm              4B: [op][d][n][m] */

/* ================================================================
 * 栈机器操作码 (Stack Machine Opcodes)
 *
 * 所有 S_* 操作码操作 eval_stk[] 操作栈，
 * 操作数隐式从栈顶取，结果 push 回栈顶。
 * 彻底消除寄存器冲突问题。
 *
 * 值域选择: 仅使用与旧 register-based 操作码不冲突的空闲字节值。
 * ================================================================ */

/* ---- 栈 ↔ 寄存器传输 ---- */
#define OP_S_VLOAD 0x01  /* push R[r]             2B: [op][r] */
#define OP_S_VSTORE 0x02 /* pop → R[r]            2B: [op][r] */

/* ---- 栈立即数 ---- */
#define OP_S_PUSH_IMM32 0x03 /* push imm32            5B: [op][imm32] */
#define OP_S_PUSH_IMM64 0x04 /* push imm64            9B: [op][imm64] */

/* ---- 栈控制 ---- */
#define OP_S_DUP 0x05  /* dup 栈顶              1B */
#define OP_S_SWAP 0x06 /* swap 栈顶两元素       1B */
#define OP_S_DROP 0x07 /* pop 丢弃              1B */

/* ---- 栈 ALU (二元: pop b, pop a, push result) ---- */
#define OP_S_ADD 0x09   /* push a+b              1B */
#define OP_S_SUB 0x0A   /* push a-b              1B */
#define OP_S_MUL 0x0B   /* push a*b              1B */
#define OP_S_XOR 0x0C   /* push a^b              1B */
#define OP_S_AND 0x0D   /* push a&b              1B */
#define OP_S_OR 0x0E    /* push a|b              1B */
#define OP_S_SHL 0x0F   /* push a<<b             1B */
#define OP_S_SHR 0x10   /* push a>>b (logical)   1B */
#define OP_S_ASR 0x11   /* push a>>b (arith)     1B */
#define OP_S_ROR 0x12   /* push ror(a,b)         1B */
#define OP_S_UMULH 0x13 /* push umulh(a,b)       1B */
#define OP_S_SMULH 0x14 /* push smulh(a,b)       1B */
#define OP_S_UDIV 0x7B  /* push a/b (unsigned)   1B */
#define OP_S_SDIV 0x7C  /* push a/b (signed)     1B */
#define OP_S_ADC 0x7D   /* push a+b+carry        1B */
#define OP_S_SBC 0x7E   /* push a-b-(1-carry)    1B */

/* ---- 栈 ALU (一元: pop a, push result) ---- */
#define OP_S_NOT 0x7F     /* push ~a               1B */
#define OP_S_CLZ 0x80     /* push clz(a)           1B */
#define OP_S_CLS 0x81     /* push cls(a)           1B */
#define OP_S_RBIT 0x82    /* push rbit(a)          1B */
#define OP_S_REV 0x84     /* push bswap64(a)       1B */
#define OP_S_REV16 0x85   /* push rev16(a)         1B */
#define OP_S_REV32 0x86   /* push rev32(a)         1B */
#define OP_S_TRUNC32 0x87 /* push a & 0xFFFFFFFF   1B */
#define OP_S_SEXT32 0x88  /* push sext32(a)        1B */

/* ---- 栈比较 ---- */
#define OP_S_CMP 0x89 /* pop b,a → set flags   1B */

/* ---- 栈内存访问 (pop addr, push/pop value) ---- */
#define OP_S_LD8 0x8A  /* pop addr → push *(u8*)addr   1B */
#define OP_S_LD16 0x8B /* pop addr → push *(u16*)addr  1B */
#define OP_S_LD32 0x92 /* pop addr → push *(u32*)addr  1B */
#define OP_S_LD64 0x93 /* pop addr → push *(u64*)addr  1B */
#define OP_S_ST8 0x94  /* pop val,addr → *(u8*)addr=val   1B */
#define OP_S_ST16 0x95 /* pop val,addr → *(u16*)addr=val  1B */
#define OP_S_ST32 0x96 /* pop val,addr → *(u32*)addr=val  1B */
#define OP_S_ST64 0x97 /* pop val,addr → *(u64*)addr=val  1B */

/* ---- 栈设置标志位 ---- */
#define OP_S_AD_SETFLAGS 0x98 /* pop result,bits,hasCarry,b,a → set flags 1B */
#define OP_S_SU_SETFLAGS 0x99 /* pop result,bits,hasCarry,b,a → set flags 1B */

#endif /* VM_OPCODES_H */
