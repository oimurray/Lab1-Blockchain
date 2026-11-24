// feistel.cpp — custom Feistel block cipher (Task 1)
#include "feistel.hpp"
#include <bit>

namespace feistel {

// S-box (confusion)
// next: choose your S-box. Options:
//   - design your own (then you must argue for its nonlinearity in the report)


// ---------------------------------------------------------------------------
// Key schedule
// next: derive ROUNDS different 32-bit subkeys from the 128-bit key.
// Things to think about:
//   - every subkey should depend on many key bits, and no two should be equal
//   - round constants stop rounds from looking identical (slide attacks)
//   - running the S-box over key material adds nonlinearity to the schedule
// Placeholder below just cycles through the four 32-bit words of the key.
// ---------------------------------------------------------------------------
Subkeys key_schedule(const Key64& key) {
    Subkeys K{};

    for (int i = 0; i < ROUNDS; ++i) {
        K[i] = w[i % 4];   //: replace with your real schedule
    }
    return K;
}

// ---------------------------------------------------------------------------
// Round function F
// next: design F. Criteria from lecture 3, slides 64-65:
//   - nonlinear (confusion)       -> e.g. sub_word(...)
//   - good avalanche (diffusion)  -> e.g. std::rotl, XOR / modular addition of rotated copies
//   - bit independence
// Remember: a byte-wise S-box alone never moves bits between bytes; you need a mixing step.
// Placeholder below is R XOR K: linear, the "trivial construction" the sheet forbids.
// ---------------------------------------------------------------------------
uint32_t f(uint32_t half, uint32_t subkey) {
    uint32_t x = half ^ subkey;    // step 1: XOR with the subkey
    
    // step 2: confusion  — TODO, e.g. x = sub_word(x);
    
    // step 3: diffusion  — TODO, e.g. combine x with rotated copies of itself

                   // remove this line once you use sub_word
    return x;
}

// ---------------------------------------------------------------------------
// Feistel structure — complete; works for ANY f (slides 43-49).
//   L_i = R_{i-1},   R_i = L_{i-1} XOR f(R_{i-1}, K_i)
// Final swap so that decryption = same function with reversed subkeys.
// ---------------------------------------------------------------------------
uint64_t block(uint64_t in, const Subkeys& K, bool decrypt, RoundStates* states) {
    uint32_t L = uint32_t(in >> 32);
    uint32_t R = uint32_t(in);

    if (states) (*states)[0] = (uint64_t(L) << 32) | R;

    for (int i = 0; i < ROUNDS; ++i) {
        if (decrypt) {
            k = K[ROUNDS - 1 - i];
        } else k = K[i];
        uint32_t newR = L ^ f(R, k);
        L = R;
        R = newR;
        if (states) (*states)[i + 1] = (uint64_t(L) << 32) | R;
    }

    return (uint64_t(R) << 32) | L;   // undo the last swap
}

} // namespace feistel