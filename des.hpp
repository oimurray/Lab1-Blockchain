// des.hpp — DES block cipher (64-bit block, 56-bit effective key)
#pragma once
#include <array>
#include <cstdint>

using Subkeys = std::array<uint64_t, 16>;   // K1..K16, 48 bits each (stored in uint64_t)

// Rearrange bits of `in` (inBits wide) according to `table` (outBits entries,
// 1-indexed from the MSB). Used for IP, FP, E, P, PC1 and PC2.
uint64_t permute(uint64_t in, const int* table, int outBits, int inBits);

// Circular left shift of a 28-bit value.
uint32_t rotl28(uint32_t x, int shift);

// 64-bit key -> 16 round subkeys (48 bits each).
Subkeys key_schedule(uint64_t key);

// 48 bits -> eight 6-bit chunks -> eight S-box lookups -> 32 bits.
uint32_t sbox_substitute(uint64_t x48);

// DES round function: E, XOR subkey, S-boxes, P.
uint32_t f(uint32_t R, uint64_t K);

// Encrypt (decrypt = false) or decrypt (decrypt = true) one 64-bit block.
// trace = true prints the subkey and halves after every round (slide 59 format).
uint64_t des_block(uint64_t block, const Subkeys& K, bool decrypt, bool trace = false);

// Convenience wrappers
inline uint64_t des_encrypt_block(uint64_t block, const Subkeys& K) { return des_block(block, K, false); }
inline uint64_t des_decrypt_block(uint64_t block, const Subkeys& K) { return des_block(block, K, true); }