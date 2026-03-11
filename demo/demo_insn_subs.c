#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

__attribute__((noinline)) void test_subs_basic(void) {
    uint32_t flags;
    int32_t result;
    
    __asm__ volatile(
        "mov x1, #10\n"
        // "mov x2, #5\n"
        "subs x3, x1, #5\n"        // 10 - 5 = 5
        "mrs %x[fl], nzcv\n"        // 读取标志位 (存到64位寄存器)
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    printf("10 - 5 = %d, flags=0x%08x\n", result, flags);
    // flags 应该是 0x20000000
}

__attribute__((noinline)) void test_subs_zero(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf;
    
    __asm__ volatile(
        "mov x1, #10\n"
        "mov x2, #10\n"
        "subs x3, x1, x2\n"        // 10 - 10 = 0
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;  // ZF 在 bit30
    cf = (flags >> 29) & 1;  // CF 在 bit29
    nf = (flags >> 31) & 1;  // NF 在 bit31
    
    printf("10 - 10 = %d, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=1, CF=0, NF=0
}

__attribute__((noinline)) void test_subs_negative(void) {
    uint32_t flags;
    int32_t result;
    int zf, cf, nf;
    
    __asm__ volatile(
        "mov x1, #5\n"
        "mov x2, #10\n"
        "subs x3, x1, x2\n"        // 5 - 10 = -5
        "mrs %x[fl], nzcv\n"
        "mov %w[res], w3\n"
        : [res] "=r"(result), [fl] "=r"(flags)
        :
        : "x1", "x2", "x3", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    nf = (flags >> 31) & 1;
    
    printf("5 - 10 = %d, flags=0x%08x, ZF=%d, CF=%d, NF=%d\n", 
           result, flags, zf, cf, nf);
    // 应该: ZF=0, CF=1, NF=1
}

__attribute__((noinline)) void test_sbcs(void) {
       uint32_t flags;
    uint64_t result_lo, result_hi;
    int zf, cf;
    uint64_t temp;
    
    __asm__ volatile(
        // 被减数: 0x10000000000000000
        "mov x1, #1\n"               // 高64位 = 1
        "mov x2, #0\n"               // 低64位 = 0
        
        // 减数: 1
        "mov x3, #0\n"               // 高64位 = 0
        "mov x4, #1\n"               // 低64位 = 1
        
        // 低64位减法
        "subs x5, x2, x4\n"          // 0 - 1 = -1, 设置借位
        
        // 高64位带借位减法
        "sbcs x6, x1, x3\n"          // 1 - 0 - 1 = 0
        
        // 现在检查整个128位结果是否为0
        "orr %x[tmp], x5, x6\n"      // 合并高低64位
        "cmp %x[tmp], #0\n"          // 比较是否为0
        "mrs %x[fl], nzcv\n"         // 读取最终标志位
        
        "mov %x[lo], x5\n"
        "mov %x[hi], x6\n"
        : [lo] "=r"(result_lo), [hi] "=r"(result_hi), 
          [fl] "=r"(flags), [tmp] "=r"(temp)
        :
        : "x1", "x2", "x3", "x4", "x5", "x6", "cc"
    );
    
    zf = (flags >> 30) & 1;
    cf = (flags >> 29) & 1;
    
    printf("SBCS: 0x10000000000000000 - 1 = 0x%lx%016lx\n", 
           result_hi, result_lo);
    printf("flags=0x%08x, ZF=%d, CF=%d\n", flags, zf, cf);
}

__attribute__((noinline)) void test_sbcs_with_branch(void) {
    uint32_t flags;
    int64_t result;
    int branch_taken = 0;
    
    __asm__ volatile(
        "mov x1, #5\n"
        "mov x2, #10\n"
        
        // 第一次减法: 5 - 10 = -5, 设置 CF=1
        "subs x3, x1, x2\n"
        
        // 第二次带借位减法: -5 - 2 - 1 = -8
        "mov x4, #2\n"
        "sbcs x5, x3, x4\n"
        
        // 测试分支: 如果 CF=1 则跳转 (应该有借位)
        "b.cs 1f\n"                   // CS = Carry Set (CF=1)
        "mov %w[br], #0\n"            // 分支未执行
        "b 2f\n"
        "1:\n"
        "mov %w[br], #1\n"            // 分支已执行
        "2:\n"
        
        "mrs %x[fl], nzcv\n"
        "mov %x[res], x5\n"
        : [res] "=r"(result), [fl] "=r"(flags), [br] "=r"(branch_taken)
        :
        : "x1", "x2", "x3", "x4", "x5", "cc"
    );
    
    printf("SBCS with branch: result=%ld, flags=0x%08x, branch_taken=%d\n", 
           result, flags, branch_taken);
}

int main(void) {
    printf("=== Testing SUBS ===\n");
    test_subs_basic();
    test_subs_zero();
    test_subs_negative();
    
    printf("\n=== Testing SBCS ===\n");
    test_sbcs();
    test_sbcs_with_branch();
    
    return 0;
}
/*
    预期打印
    === Testing SUBS ===
    10 - 5 = 5, flags=0x20000000
    10 - 10 = 0, flags=0x60000000, ZF=1, CF=1, NF=0
    5 - 10 = -5, flags=0x80000000, ZF=0, CF=0, NF=1

    === Testing SBCS ===
    SBCS: 0x10000000000000000 - 1 = 0x0ffffffffffffffff
    flags=0xa0000000, ZF=0, CF=1
    SBCS with branch: result=-8, flags=0xa0000000, branch_taken=1
*/