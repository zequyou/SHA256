#include <stdint.h>
#include "SHA256.h"

static uint32_t rotate_right(uint32_t bits, uint32_t word) {
    return (word >> bits) | (word << (32-(bits)));
}

static uint32_t BSIG0(uint32_t x) {
    return rotate_right(2u, x) ^ rotate_right(13u, x) ^ rotate_right(22u, x);
}

static uint32_t BSIG1(uint32_t x) {
    return rotate_right(6u, x) ^ rotate_right(11u, x) ^ rotate_right(25u, x);
}

static uint32_t SSIG0(uint32_t src) {
    return rotate_right(7u, src) ^ rotate_right(18u, src) ^ (src >> 3u);
}

static uint32_t SSIG1(uint32_t src) {
    return rotate_right(17u, src) ^ rotate_right(19u, src) ^ (src >> 10u);
}

static uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

const uint32_t k_table[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};


uint32_t SHA256_padding_5(uint8_t *buffer, uint32_t length) {
    // step A: append "1"
    buffer[length] = 0x80u;

    // step B: append K "0"
    uint32_t zero_byte_count = 0;
    uint32_t chunk_count = length / 64 + 1;
    if (length % 64 >= 56) {
        zero_byte_count = 119 - length % 64;
        chunk_count++;
    } else {
        zero_byte_count = 55 - length % 64;
    }
    for (uint32_t i = 1; i <= zero_byte_count; i++) {
        buffer[length + i] = 0;
    }

    // stop C: append 64 bits length
    uint8_t part5 = ((length * 8) >> (16u)) & 0x000000FFu;
    uint8_t part6 = ((length * 8) >> (8u)) & 0x000000FFu;
    uint8_t part7 = ((length * 8) >> (0u)) & 0x000000FFu;
    buffer[length + zero_byte_count + 1] = 0;
    buffer[length + zero_byte_count + 2] = 0;
    buffer[length + zero_byte_count + 3] = 0;
    buffer[length + zero_byte_count + 4] = 0;
    buffer[length + zero_byte_count + 5] = 0;
    buffer[length + zero_byte_count + 6] = part5;
    buffer[length + zero_byte_count + 7] = part6;
    buffer[length + zero_byte_count + 8] = part7;

    return chunk_count;
}


#pragma SDS data mem_attribute(buffer:PHYSICAL_CONTIGUOUS, hash:PHYSICAL_CONTIGUOUS)
#pragma SDS data access_pattern(buffer:SEQUENTIAL, hash:SEQUENTIAL)
#pragma SDS data zero_copy(buffer[0:8 * chunk_count], hash[0:8])
void SHA256_processing_5(const uint64_t buffer[1024], uint16_t chunk_count, uint32_t hash[8]) {
    uint32_t H[8];
    uint32_t W0[32];
    uint32_t W1[32];

	H[0] = 0x6a09e667u;
	H[1] = 0xbb67ae85u;
	H[2] = 0x3c6ef372u;
	H[3] = 0xa54ff53au;
	H[4] = 0x510e527fu;
	H[5] = 0x9b05688cu;
	H[6] = 0x1f83d9abu;
	H[7] = 0x5be0cd19u;

	#pragma HLS array_partition variable=H complete

    for (uint16_t i = 0; i < chunk_count; i++) {
        #pragma HLS LOOP_TRIPCOUNT min=64 max=128

        for (uint8_t k = 0; k < 8; k++) {
            #pragma HLS PIPELINE II=1
            uint64_t value = buffer[i * 8 + k];
            uint8_t part7 = (uint8_t) ((value & 0xFF00000000000000u) >> 56u);
            uint8_t part6 = (uint8_t) ((value & 0x00FF000000000000u) >> 48u);
            uint8_t part5 = (uint8_t) ((value & 0x0000FF0000000000u) >> 40u);
            uint8_t part4 = (uint8_t) ((value & 0x000000FF00000000u) >> 32u);
            uint8_t part3 = (uint8_t) ((value & 0x00000000FF000000u) >> 24u);
            uint8_t part2 = (uint8_t) ((value & 0x0000000000FF0000u) >> 16u);
            uint8_t part1 = (uint8_t) ((value & 0x000000000000FF00u) >> 8u);
            uint8_t part0 = (uint8_t) ((value & 0x00000000000000FFu) >> 0u);
            W0[k] = ((uint32_t) part0) << 24u;
            W0[k] |= ((uint32_t) part1) << 16u;
            W0[k] |= ((uint32_t) part2) << 8u;
            W0[k] |= ((uint32_t) part3) << 0u;
            W1[k] = ((uint32_t) part4) << 24u;
            W1[k] |= ((uint32_t) part5) << 16u;
            W1[k] |= ((uint32_t) part6) << 8u;
            W1[k] |= ((uint32_t) part7) << 0u;
        }

        // generate w 16-63
        for (uint8_t l = 8; l < 32; l++) {
            #pragma HLS PIPELINE II=3
            W0[l] = W0[l - 8] + SSIG0(W1[l - 8]) + W1[l - 4] + SSIG1(W0[l - 1]);
            W1[l] = W1[l - 8] + SSIG0(W0[l - 7]) + W0[l - 3] + SSIG1(W1[l - 1]);
        }

        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        for (uint8_t m = 0; m < 64; m++) {
			#pragma HLS PIPELINE
            uint32_t T1 = 0;
            if (m % 2 == 0) {
                T1 = h + BSIG1(e) + CH(e, f, g) + k_table[m] + W0[m / 2];
            } else {
                T1 = h + BSIG1(e) + CH(e, f, g) + k_table[m] + W1[m / 2];
            }
            uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    for (uint8_t l = 0; l < 8; l++) {
        #pragma HLS PIPELINE
        hash[l] = H[l];
    }
}
