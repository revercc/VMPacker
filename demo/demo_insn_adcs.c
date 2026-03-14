#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

__attribute__((noinline)) void test_adds_basic(void) {
    uint32_t flags;
    int32_t result;
    
    __asm__ volatile(
        "mov x1, #10\n"
        "adds x3, x1, #5\n"        // 10 + 5 = 15
        "mrs %x[fl], nzcv\n"        // 读取标志位
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x3", "cc"
    );
    
    printf("10 + 5 = %d, flags=0x%08x\n", result, flags);
    // flags 应该是 0x00000000 (C=0)
}

__attribute__((noinline)) void test_adds_zero(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf, vf;
    
    __asm__ volatile(
        "mov x1, #0\n"
        "mov x2, #0\n"
        "adds x3, x1, x2\n"        // 0 + 0 = 0
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;  // ZF 在 bit30
    cf = (flags >> 29) & 1;  // CF 在 bit29
    nf = (flags >> 31) & 1;  // NF 在 bit31
    
    printf("0 + 0 = %d, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=1, CF=0, NF=0
}

__attribute__((noinline)) void test_adds_unsigned_overflow(void) {
    uint32_t flags;
    uint32_t result;
    int zf, cf, nf, vf;
    
    __asm__ volatile(
        "mov w1, #0xffffffff\n"     // 最大无符号32位数
        "mov w2, #1\n"
        "adds w3, w1, w2\n"         // 0xffffffff + 1 = 0, 产生进位
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    nf = (flags >> 31) & 1;
    
    printf("0xffffffff + 1 = 0x%08x, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=1, CF=1, NF=0
}

__attribute__((noinline)) void test_adds_negative_plus_negative(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf, vf;
    
    __asm__ volatile(
        "mov w1, #-5\n"             // 0xfffffffb
        "mov w2, #-3\n"             // 0xfffffffd
        "adds w3, w1, w2\n"         // -5 + -3 = -8
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    nf = (flags >> 31) & 1;
    
    printf("(-5) + (-3) = %d, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=0, CF=1, NF=1
}


__attribute__((noinline)) void test_adcs_with_branch(void) {
    uint32_t flags;
    int64_t result;
    int branch_taken = 0;
    
    __asm__ volatile(
        "mov x1, #5\n"
        "mov x2, #10\n"
        
        // 第一次加法: 5 + 10 = 15, 设置 CF=0
        "adds x3, x1, x2\n"
        
        // 第二次带进位加法: 15 + 2 + CF(0) = 17, 设置 CF=0
        "mov x4, #2\n"
        "adcs x5, x3, x4\n"
        
        // 测试分支: 如果 CC (Carry Clear, CF=0) 则跳转
        "b.cc 1f\n"                   // CC = Carry Clear (CF=0)
        "mov %w[br], #0\n"            // 分支未执行
        "b 2f\n"
        "1:\n"
        "mov %w[br], #1\n"            // 分支已执行 (CF=0, 所以应该执行)
        "2:\n"
        
        "mrs %x[fl], nzcv\n"
        "mov %x[res], x5\n"
        : [res] "=r"(result), [fl] "=r"(flags), [br] "=r"(branch_taken)
        :
        : "x1", "x2", "x3", "x4", "x5", "cc"
    );
    
    printf("ADCS with branch (CC): result=%ld, flags=0x%08x, branch_taken=%d\n", 
           result, flags, branch_taken);
    // 应该: branch_taken=1 (因为CF=0, CC条件成立)
}

__attribute__((noinline)) void test_adcs_branch_on_carry(void) {
    uint32_t flags;
    int64_t result;
    int branch_taken = 0;
    
    __asm__ volatile(
        // 设置进位标志: 使用大数加法产生进位
        "mov w1, #0xffffffff\n"      // 最大32位数
        "mov w2, #1\n"
        "adds w3, w1, w2\n"          // 0xffffffff + 1 = 0, 设置 CF=1
        
        // 带进位加法: 5 + 10 + CF(1) = 16
        "mov x4, #5\n"
        "mov x5, #10\n"
        "adcs x6, x4, x5\n"          // 5 + 10 + CF(1) = 16, 设置 CF=0
        
        // 测试分支: 如果 CS (Carry Set, CF=1) 则跳转
        "b.cs 1f\n"                   // CS = Carry Set (CF=1)
        "mov %w[br], #0\n"            // 分支已执行 (CF=0, 所以应该执行)
        "b 2f\n"
        "1:\n"
        "mov %w[br], #1\n"            // 分支未执行
        "2:\n"
        
        "mrs %x[fl], nzcv\n"
        "mov %x[res], x6\n"
        : [res] "=r"(result), [fl] "=r"(flags), [br] "=r"(branch_taken)
        :
        : "w1", "w2", "w3", "x4", "x5", "x6", "cc"
    );
    
    printf("ADCS with branch (CS): result=%ld, flags=0x%08x, branch_taken=%d\n", 
           result, flags, branch_taken);
    // 应该: branch_taken=0 (因为CF=0, CS条件不成立)
}

int main(void) {
    printf("=== Testing ADDS ===\n");
    test_adds_basic();
    test_adds_zero();
    test_adds_unsigned_overflow();
    test_adds_negative_plus_negative();
    
    printf("\n=== Testing ADCS ===\n");
    test_adcs_with_branch();
    test_adcs_branch_on_carry();
    
    return 0;
}

/*
    预期打印:
    === Testing ADDS ===
    10 + 5 = 15, flags=0x00000000
    0 + 0 = 0, flags=0x40000000, ZF=1, CF=0, NF=0
    0xffffffff + 1 = 0x00000000, flags=0x60000000, ZF=1, CF=1, NF=0
    (-5) + (-3) = -8, flags=0xa0000000, ZF=0, CF=1, NF=1

    === Testing ADCS ===
    ADCS with branch (CC): result=17, flags=0x00000000, branch_taken=1
    ADCS with branch (CS): result=16, flags=0x00000000, branch_taken=0
*/