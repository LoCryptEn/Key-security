#include <stdio.h>
#include <stdint.h>

// 声明在汇编中实现的函数
// 假设 bignum_montmul_n256 以指针形式接收输出缓冲区
extern void bignum_montmul_n256(uint64_t *out);

// 定义两个 256-bit 输入数据
static uint64_t xHigh[2] = {
    0x1111111111111111ULL,
    0x2222222222222222ULL,
};

static uint64_t xLow[2] = {
    0x3333333333333333ULL,
    0x4444444444444444ULL,
};

static uint64_t yHigh[4] = {
    0x5555555555555555ULL,
    0x6666666666666666ULL,
};

static uint64_t yLow[4] = {
    0x7777777777777777ULL,
    0x8888888888888888ULL,
};

int main(void) {
    // 用于存放计算结果
    uint64_t result[4] = {0};

    // 将 xVal, yVal 放入 xmm28-xmm31
    __asm__ __volatile__ (
        "vmovdqa64  (%0), %%xmm28      \n\t"
        "vmovdqa64  16(%0), %%xmm29    \n\t"
        "vmovdqa64  (%1), %%xmm30      \n\t"
        "vmovdqa64  16(%1), %%xmm31    \n\t"
        :
        : "r"(xHigh), "r"(xLow), "r"(yHigh), "r"(yLow) 
        : "xmm28", "xmm29", "xmm30", "xmm31"
    );

    // 调用汇编函数进行乘法
    bignum_montmul_n256(result);

    // 打印结果 (高位在最后)
    printf("Result = %016llx %016llx %016llx %016llx\n",
           (unsigned long long)result[3],
           (unsigned long long)result[2],
           (unsigned long long)result[1],
           (unsigned long long)result[0]);

    return 0;
}