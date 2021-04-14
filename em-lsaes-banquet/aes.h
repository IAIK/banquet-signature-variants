#pragma once

#include "field.h"
#include "gsl-lite.hpp"
#include "types.h"
#include <array>
#include <cstdint>
#include <vector>

namespace AES128 {
constexpr size_t NUM_SBOXES = 40;
constexpr size_t BLOCK_SIZE = 16;
constexpr size_t KEY_SIZE = 16;
constexpr size_t NUM_BLOCKS = 1;

bool aes_128(const std::vector<uint8_t> &key_in,
             const std::vector<uint8_t> &plaintext_in,
             std::vector<uint8_t> &ciphertext_out);

std::pair<std::vector<field::GF2E32>, std::vector<field::GF2E32>>
aes_128_with_sbox_output(const std::vector<uint8_t> &key_in,
                         const std::vector<uint8_t> &plaintext_in,
                         std::vector<uint8_t> &ciphertext_out);

void aes_128_s_shares(const std::vector<gsl::span<uint8_t>> &key_in,
                      const std::vector<gsl::span<field::GF2E32>> &t_shares,
                      const std::vector<uint8_t> &plaintext_in,
                      std::vector<gsl::span<uint8_t>> &ciphertext_shares_out,
                      std::vector<gsl::span<field::GF2E32>> &s_shares_out);

} // namespace AES128
