// feistel.hpp — custom Feistel block cipher (Task 1)
//
// Design summary (fill in as you decide, and copy into the report):
//   Block size : 64 bits (two 32-bit halves)        TODO: justify
//   Key size   : 128 bits                           TODO: justify
//   Rounds     : ROUNDS (below)                     TODO: justify with avalanche results
//   F          : TODO: describe confusion + diffusion components
//   Key sched. : TODO: describe how subkeys are derived
#pragma once
#include <array>
#include <cstdint>

namespace feistel {

// next: choose the number of rounds. Start high (e.g. 16), measure avalanche,
// then justify the final value.
constexpr int ROUNDS = 16;

struct Key128 {
    uint64_t hi;   // first 8 bytes of the key
    uint64_t lo;   // last 8 bytes of the key
};

using Subkeys = std::array<uint32_t, ROUNDS>;     // one 32-bit subkey per round
using RoundStates = std::array<uint64_t, ROUNDS + 1>;  // state before round 1 .. after last round

// Derive one subkey per round from the 128-bit master key.
Subkeys key_schedule(const Key128& key);

// Round function: 32-bit half + 32-bit subkey -> 32 bits. Does NOT need to be invertible.
uint32_t f(uint32_t half, uint32_t subkey);

// Encrypt (decrypt = false) or decrypt (decrypt = true) one 64-bit block.
// If `states` is not null, it receives L||R before the first round and after every round
// (used for the avalanche test).
uint64_t block(uint64_t in, const Subkeys& K, bool decrypt, RoundStates* states = nullptr);

inline uint64_t encrypt_block(uint64_t in, const Subkeys& K) { return block(in, K, false); }
inline uint64_t decrypt_block(uint64_t in, const Subkeys& K) { return block(in, K, true); }

} // namespace feistel