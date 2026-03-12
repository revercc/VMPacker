#include <stdio.h>
#include <stdint.h>
__attribute__((noinline)) int check_extr_all(void) {
    uint64_t out64_1 = 0, out64_2 = 0, out64_3 = 0;
    uint32_t out32 = 0;
    
    // 用 C 变量传入值
    uint64_t val64_1 = 0x123456789ABCDEF0ULL;
    uint64_t val64_2 = 0xFEDCBA9876543210ULL;
    uint32_t val32_1 = 0x12345678;
    uint32_t val32_2 = 0x9ABCDEF0;
    
    printf("\n=== Testing EXTR Instruction ===\n");
    
    // 64位 EXTR #8
    __asm__ volatile(
        "extr %0, %1, %2, #8\n"
        : "=r"(out64_1)
        : "r"(val64_1), "r"(val64_2)
        : "cc");
    printf("EXTR #8:  0x%016llx\n", out64_1);
    
    // 64位 EXTR #32
    __asm__ volatile(
        "extr %0, %1, %2, #32\n"
        : "=r"(out64_2)
        : "r"(val64_1), "r"(val64_2)
        : "cc");
    printf("EXTR #32: 0x%016llx\n", out64_2);
    
    // 64位 ROR 别名
    __asm__ volatile(
        "extr %0, %1, %1, #16\n"
        : "=r"(out64_3)
        : "r"(val64_1)
        : "cc");
    printf("EXTR ROR #16: 0x%016llx\n", out64_3);
    
    // 32位 EXTR #16
    __asm__ volatile(
        "extr %w0, %w1, %w2, #16\n"
        : "=r"(out32)
        : "r"(val32_1), "r"(val32_2)
        : "cc");
    printf("EXTR #16 (32-bit): 0x%08x\n", out32);
    
    // 验证
    int pass = 1;
    if (out64_1 != 0xF0FEDCBA98765432ULL) pass = 0;
    if (out64_2 != 0x9ABCDEF0FEDCBA98ULL) pass = 0;
    if (out64_3 != 0xDEF0123456789ABCULL) pass = 0;
    if (out32 != 0x56789ABC) pass = 0;
    
    return pass;
}

int main(void) {
    if (check_extr_all()) {
        printf("\nPASS: All EXTR tests passed\n");
        return 0;
    } else {
        printf("\nFAIL: Some EXTR tests failed\n");
        return 1;
    }
}