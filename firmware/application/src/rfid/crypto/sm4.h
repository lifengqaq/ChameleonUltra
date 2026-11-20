#ifndef CHAMELEON_SM4_H
#define CHAMELEON_SM4_H

#include <stdint.h>

#define SM4_BLOCK_SIZE 16u

/* GB/T 32907: encrypt a single 128-bit block with a 128-bit key. */
void sm4_encrypt_block(uint8_t out[SM4_BLOCK_SIZE],
    const uint8_t in[SM4_BLOCK_SIZE], const uint8_t key[SM4_BLOCK_SIZE]);

#endif
