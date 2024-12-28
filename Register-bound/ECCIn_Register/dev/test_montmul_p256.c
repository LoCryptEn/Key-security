#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Function prototype for the assembly routine
extern void bignum_montmul_n256(uint64_t z[static 4], uint64_t x[static 4], uint64_t y[static 4]);

// Helper function to print a 256-bit number
void print_uint256(const uint64_t x[4]) {
    printf("0x%016lx%016lx%016lx%016lx\n", x[3], x[2], x[1], x[0]);
}

// Helper function to parse a 256-bit hexadecimal string into a uint64_t array
void parse_uint256(const char *hex, uint64_t out[4]) {
    for (int i = 0; i < 4; i++) {
        sscanf(hex + (16 * (3 - i)), "%16lx", &out[i]);
    }
}

int main() {
    char input_x[65], input_y[65];
    uint64_t x[4] = {0}, y[4] = {0}, z[4] = {0};

    // Prompt the user for input
    scanf("%64s", input_x);
    scanf("%64s", input_y);

    // Parse inputs into 256-bit arrays
    parse_uint256(input_x, x);
    parse_uint256(input_y, y);

    // Call the assembly function
    bignum_montmul_n256(z, x, y);

    // Print the result
    print_uint256(z);

    return 0;
}
