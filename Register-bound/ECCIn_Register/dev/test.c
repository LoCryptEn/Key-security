#include <stdio.h>

extern void test_montmul_n256();

int main() {
    test_montmul_n256();
    printf("Test finished.\n");
    return 0;
}