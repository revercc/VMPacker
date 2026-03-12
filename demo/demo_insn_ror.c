#include <stdio.h>

__attribute__((noinline)) int check_ror(void){
    int out=-1;
    __asm__ volatile(
        "mov x1, #42\n"
        "mov x2, #0\n"
        "ror x3, x1, x2\n"
        "mov %w[o], w3\n"
        : [o] "=r"(out)
        :
        : "x1","x2","x3","memory","cc");
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
    return out;
}


__attribute__((noinline)) int check_ror_w_all(void){
    int out1 = -1, out2 = -1, out3 = -1, out4 = -1;
    
    // 用例1: 32位循环右移8位
    __asm__ volatile(
        "mov w1, #42\n"           // w1 = 42 (0x2A)
        "mov w2, #8\n"            // w2 = 8
        "ror w3, w1, w2\n"        // 42 ROR 8 = (42>>8) | (42<<24)
        "mov %w[o1], w3\n"
        : [o1] "=r"(out1)
        :
        : "w1", "w2", "w3", "memory", "cc");
    
    // 用例2: 32位循环右移0位（应该不变）
    __asm__ volatile(
        "mov w1, #42\n"           // w1 = 42
        "mov w2, #0\n"            // w2 = 0
        "ror w3, w1, w2\n"        // 42 ROR 0 = 42
        "mov %w[o2], w3\n"
        : [o2] "=r"(out2)
        :
        : "w1", "w2", "w3", "memory", "cc");
    
    // 用例3: 32位循环右移16位
    __asm__ volatile(
        "mov w1, #0x5678\n"
        "movk w1, #0x1234, lsl #16\n"   // w1 = 0x12345678
        "mov w2, #16\n"                 // w2 = 16
        "ror w3, w1, w2\n"              // 0x12345678 ROR 16 = 0x56781234
        "mov %w[o3], w3\n"
        : [o3] "=r"(out3)
        :
        : "w1", "w2", "w3", "memory", "cc");
    
    // 用例4: 32位循环右移31位（相当于左移1位）
    __asm__ volatile(
        "mov w1, #0x80000000\n"   // w1 = 0x80000000 (最高位为1)
        "mov w2, #31\n"           // w2 = 31
        "ror w3, w1, w2\n"        // 0x80000000 ROR 31 = 0x00000001
        "mov %w[o4], w3\n"
        : [o4] "=r"(out4)
        :
        : "w1", "w2", "w3", "memory", "cc");
    
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
    
    // 验证结果
    if (out1 == 0x2A000000) {        // 42 ROR 8 = 0x2A000000
        printf("ROR #8: 0x%08X (PASS)\n", out1);
    } else {
        printf("ROR #8: 0x%08X (FAIL, expected 0x2A000000)\n", out1);
        return 0;
    }
    
    if (out2 == 42) {
        printf("ROR #0: %d (PASS)\n", out2);
    } else {
        printf("ROR #0: %d (FAIL, expected 42)\n", out2);
        return 0;
    }
    
    if (out3 == 0x56781234) {
        printf("ROR #16: 0x%08X (PASS)\n", out3);
    } else {
        printf("ROR #16: 0x%08X (FAIL, expected 0x56781234)\n", out3);
        return 0;
    }
    
    if (out4 == 0x00000001) {
        printf("ROR #31: 0x%08X (PASS)\n", out4);
    } else {
        printf("ROR #31: 0x%08X (FAIL, expected 0x00000001)\n", out4);
        return 0;
    }
    
    return 1;
}


int main(void){
    int v=check_ror();
    if(v==42){
        printf("PASS:ROR:%d\n",v);
    } else {
        printf("FAIL:ROR:%d\n",v);
    }

    v = check_ror_w_all();
    if (v) {
        printf("\nPASS: All ROR tests passed\n");
    } else {
        printf("\nFAIL: Some ROR tests failed\n");
    }
    return 0;
}
