#pragma once
#include "des_tables.hpp"
#include "des.hpp"


// permute: build the output one bit at a time.
// table[i] names which input bit (1 = leftmost of inBits) becomes output bit i+1.
// Input bit n (from the left) sits at position (inBits - n) counting from the LSB.
uint64_t permute(uint64_t in, const int* table, int outBits, int inBits) {
    uint64_t out = 0;
    for (int i = 0; i < outBits; i++) {
        uint64_t bit = (in >> (inBits - table[i])) & 1; 
        out = (out << 1) | bit;
    }
    return out;
}

// rotl28: rotate a 28-bit value left. Bits leaving the top re-enter at the
// bottom; the mask discards anything that spilled above bit 27.0x0FFFFFFF
// Circular left shift of a 28-bit value.  
uint32_t rotl28(uint32_t x, int shift) {
    return ((x << shift) | (x >> (28 - shift))) & 0x0FFFFFFF;
}


// key_schedule: PC1 (64 -> 56), split into C and D, then per round:
// rotate both halves, join them, PC2 (56 -> 48) = subkey for that round.
// ---
// 64-bit key -> 16 round subkeys (48 bits each).
Subkeys key_schedule(uint64_t key) {
    Subkeys K{};
    uint64_t k56 = permute(key, PC1, 56, 64); 
    uint32_t C = uint32_t(k56 >> 28) & 0x0FFFFFFF;
    uint32_t D = uint32_t(k56) & 0x0FFFFFFF;

    for (int i = 0; i < 16; i++) {
        C = rotl28(C, SHIFTS[i]);
        D = rotl28(D, SHIFTS[i]);
        uint64_t CD = (uint64_t(C) << 28) | (D);
        K[i] = permute(CD, PC2, 48, 56);
    }

    return K;
}


// sbox_substitute: split 48 bits into eight 6-bit chunks (S1 gets the leftmost).
// For each chunk b1..b6: row = b1b6 (outer bits), col = b2b3b4b5 (middle bits).
// Concatenate the eight 4-bit outputs into 32 bits.

// 48 bits -> eight 6-bit chunks -> eight S-box lookups -> 32 bits.
uint32_t sbox_substitute(uint64_t x48) {
    uint32_t out = 0;

    for (int i = 0; i < 8; i++) {
        int chunk = int((x48 >> (42 - 6 * i)) & 0x3F);
        int row = ((chunk >> 4) & 0x2) | (chunk & 0x1);
        int col = ((chunk >> 1) & 0xF);
        out = (out << 4) | SBOX[i][row][col]; // use the table to decide what the output looks like
    }
}

// DES round function: E, XOR subkey, S-boxes, P.
uint32_t f(uint32_t R, uint64_t K) {
    uint64_t expanded = permute(R, E, 48, 32);
    uint64_t mixed = expanded ^ K;
    uint32_t sub = sbox_substitute(mixed);
    return uint32_t(permute(sub, P, 32, 32));
}

// Encrypt (decrypt = false) or decrypt (decrypt = true) one 64-bit block.
// trace = true prints the subkey and halves after every round (slide 59 format).
uint64_t des_block(uint64_t block, const Subkeys& K, bool decrypt, bool trace = false) {
    block = permute(block, IP, 64, 64);
    uint32_t L = uint32_t(block >> 32);
    uint32_t R = uint32_t(block);

    if (trace) std::printf("IP                    %08x  %08x\n", L, R); //to debug output 

    for (int i = 0; i < 16; i++) {
        if (decrypt) {
            k = K[15 - i];
        } else k = K[i];
        uint32_t newR = L ^ f(R, k);
        L = R;
        R = newR;

        if (trace) { // more debugging
            std::printf("%2d  ", i + 1);
            print_subkey(k);
            std::printf("  %08x  %08x\n", L, R);
        }
    }

    uint64_t preoutput = (uint64_t(R) << 32) | L; // undo the final swap
    uint64_t out = permute(out, FP, 64, 64); // complete the final permutation

    if (trace) std::printf("IP^-1                 %08x  %08x\n", uint32_t(out >> 32), uint32_t(out)); // more debugging
    return out;
}

static void print_subkey(uint64_t k48) { // more claude debugging
    for (int i = 0; i < 8; ++i)
        std::printf("%02x", unsigned((k48 >> (42 - 6 * i)) & 0x3F));
}

// Convenience wrappers
inline uint64_t des_encrypt_block(uint64_t block, const Subkeys& K) { return des_block(block, K, false); }
inline uint64_t des_decrypt_block(uint64_t block, const Subkeys& K) { return des_block(block, K, true); }