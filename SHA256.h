//
// Created by developer on 10/10/19.
//

#ifndef SHA256_SHA256_H
#define SHA256_SHA256_H

#include <stdint.h>
#include <stdio.h>

void SHA256_processing_5(const uint64_t buffer[1024], uint16_t chunk_count, uint32_t hash[8]);
uint32_t SHA256_padding_5(uint8_t *buffer, uint32_t length);

#endif //SHA256_SHA256_H
