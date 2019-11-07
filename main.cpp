#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include "SHA256.h"
#include "golden.h"

#define BUFFER_SIZE 8192

int main() {
    uint32_t origin_result[16];
    uint8_t result[64];
    uint8_t golden[64];

    srandom(time(nullptr));

    for (int i = 3584; i <= 8192; i++) {
    	uint8_t input[BUFFER_SIZE + 64];

        for (uint64_t j = 0; j < i; j++) {
        	uint8_t value = random();
        	input[j] = value;
        }

        input[0] = 0x61u;
        input[1] = 0x62u;
        input[2] = 0x63u;
        input[3] = 0x64u;
        input[4] = 0x65u;
        input[5] = 0x66u;
        input[6] = 0x67u;
        input[7] = 0x68u;
        input[8] = 0x69u;
        input[9] = 0x70u;

        uint32_t chunk_count = SHA256_padding_5(input, i);
        SHA256_processing_5((uint64_t *)input, chunk_count, (uint32_t *)origin_result);

        for (int l = 0; l < 8; l++) {
            result[l * 4 + 0] = origin_result[l] >> 24u;
            result[l * 4 + 1] = origin_result[l] >> 16u;
            result[l * 4 + 2] = origin_result[l] >> 8u;
            result[l * 4 + 3] = origin_result[l] >> 0u;
        }

        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, input, i);
        sha256_final(&ctx, golden);

        for (int j = 0; j < 32; j++) {
            if (result[j] != golden[j]) {
            	printf("length i is %d\n", i);
                printf("test fail\n");
                exit(0);
            }
        }
    }

    printf("test passed!\n");

    return 0;
}
