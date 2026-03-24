#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

__attribute__((noinline)) void test_ands_zeros(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf;
    
    __asm__ volatile(
        "mov x0, #0x20000000\n"      // 预设 C=1
        "msr nzcv, x0\n"
        "mov x1, #0x0F\n"          // x1 = 0x0F
        "mov x2, #0xF0\n"          // x2 = 0xF0
        "ands x3, x1, x2\n"        // 0x0F & 0xF0 = 0
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;  // ZF 在 bit30
    cf = (flags >> 29) & 1;  // CF 在 bit29 (ANDS 通常清零 CF)
    nf = (flags >> 31) & 1;  // NF 在 bit31
    
    printf("0x0F & 0xF0 = 0x%x, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=1 (结果为0), CF=0 (ANDS 不设置 CF), NF=0 (结果非负)
}

__attribute__((noinline)) void test_ands_positive(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf;
    
    __asm__ volatile(
        "mov x0, #0x20000000\n"      // 预设 C=1
        "msr nzcv, x0\n"
        "mov x1, #0x7F\n"          // x1 = 0x7F (正数)
        "mov x2, #0x0F\n"          // x2 = 0x0F
        "ands x3, x1, x2\n"        // 0x7F & 0x0F = 0x0F
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    nf = (flags >> 31) & 1;
    
    printf("0x7F & 0x0F = 0x%x, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=0 (结果非零), CF=0, NF=0 (结果的最高位为0)
}

__attribute__((noinline)) void test_ands_negative(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf;
    
    __asm__ volatile(
        "mov x0, #0x20000000\n"      // 预设 C=1
        "msr nzcv, x0\n"
        "mov x1, #0x80\n"          // x1 = 0x80 (负数 if 8-bit, 但在32位中仍是正数)
        "mov x2, #0x80\n"          // 为了得到负结果，需要让结果的最高位为1
        "ands x3, x1, x2\n"        // 0x80 & 0x80 = 0x80 (在32位中, bit31=0)
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    nf = (flags >> 31) & 1;
    
    printf("0x80 & 0x80 = 0x%x, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 注意: 在32位上下文中，0x80 = 128，是正数，所以NF应为0
}

__attribute__((noinline)) void test_ands_negative_32bit(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf;
    
    __asm__ volatile(
        "mov x0, #0x20000000\n"      // 预设 C=1
        "msr nzcv, x0\n"
        "mov x1, #0x80000000\n"     // x1 = 0x80000000 (负数，最高位为1)
        "mov x2, #0x80000000\n"     // x2 = 0x80000000
        "ands x3, x1, x2\n"         // 0x80000000 & 0x80000000 = 0x80000000
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    nf = (flags >> 31) & 1;
    
    printf("0x80000000 & 0x80000000 = 0x%x, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=0 (结果非零), CF=0, NF=1 (结果的最高位为1，表示负数)
}


int main(void) {
    printf("=== Testing ANDS ===\n");
    test_ands_zeros();
    test_ands_positive();
    test_ands_negative();
    test_ands_negative_32bit();

    return 0;
}