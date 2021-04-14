#include "aes.h"
#include <cassert>

namespace {

#define ROTL8(x, shift) ((uint8_t)((x) << (shift)) | ((x) >> (8 - (shift))))
constexpr unsigned char AES_SBOX_AFFINE_CONST = 0x63;

unsigned char multiply(unsigned int a, unsigned int b) {
  unsigned char result = 0;

  for (int i = 0; i < 8; ++i) {
    uint8_t mask = -(b & 1);
    result ^= (a & mask);
    uint16_t mask2 = -((uint16_t)(a >> 7) & 1);
    a <<= 1;
    a ^= (0x11b & mask2);
    b >>= 1;
  }
  return result;
}

unsigned char xtime(unsigned char c) { return multiply(c, 2); }

bool wordsub(unsigned char *in, unsigned char *out) {
  field::GF2E32 s;
  s.from_bytes(in);
  if (s == field::GF2E32(0))
    return false;
  field::GF2E32 t = s.inverse();
  t.to_bytes(out);

  for (int i = 0; i < 4; i++) {
    unsigned char b = out[i];
    out[i] = b ^ ROTL8(b, 1) ^ ROTL8(b, 2) ^ ROTL8(b, 3) ^ ROTL8(b, 4) ^
             AES_SBOX_AFFINE_CONST;
  }

  return true;
}

bool wordsub_save(unsigned char *in, unsigned char *out,
                  std::pair<field::GF2E32, field::GF2E32> &save) {

  save.first.from_bytes(in);
  if (save.first == field::GF2E32(0))
    return false;
  save.second = save.first.inverse();
  save.second.to_bytes(out);

  for (int i = 0; i < 4; i++) {
    unsigned char b = out[i];
    out[i] = b ^ ROTL8(b, 1) ^ ROTL8(b, 2) ^ ROTL8(b, 3) ^ ROTL8(b, 4) ^
             AES_SBOX_AFFINE_CONST;
  }

  return true;
}

void wordsub_restore(const field::GF2E32 &t, unsigned char *out) {
  t.to_bytes(out);
  for (int i = 0; i < 4; i++) {
    unsigned char b = out[i];
    out[i] = b ^ ROTL8(b, 1) ^ ROTL8(b, 2) ^ ROTL8(b, 3) ^ ROTL8(b, 4);
  }
}

} // namespace

namespace AES128 {
static bool aes_128_old(const uint8_t *key, const uint8_t *plaintext,
                        uint8_t *ciphertext) {
  unsigned char expanded[4][44];
  unsigned char state[4][4];
  unsigned char newstate[4][4];
  unsigned char roundconstant;
  int i;
  int j;
  int r;

  // make public permutation
  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      expanded[i][j] = plaintext[j * 4 + i];

  roundconstant = 1;
  for (j = 4; j < 44; ++j) {
    unsigned char temp[4], temp2[4];
    if (j % 4)
      for (i = 0; i < 4; ++i)
        temp[i] = expanded[i][j - 1];
    else {
      for (i = 0; i < 4; ++i) {
        temp[i] = expanded[i][j - 1];
      }
      field::GF2E32 s;
      s.from_bytes(temp);
      field::GF2E32 t = s.inverse();
      t.to_bytes(temp2);
      // rotword
      for (i = 0; i < 4; ++i) {
        temp[i] = temp2[(i + 1) % 4];
      }
      temp[0] ^= roundconstant;
      roundconstant = xtime(roundconstant);
    }
    for (i = 0; i < 4; ++i)
      expanded[i][j] = temp[i] ^ expanded[i][j - 4];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      state[i][j] = key[j * 4 + i] ^ expanded[i][j];

  for (r = 0; r < 10; ++r) {
    for (i = 0; i < 4; ++i) {
      if (!wordsub(&state[i][0], &newstate[i][0]))
        return false;
    }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[i][j] = newstate[i][(j + i) % 4];
    if (r < 9)
      for (j = 0; j < 4; ++j) {
        unsigned char a0 = state[0][j];
        unsigned char a1 = state[1][j];
        unsigned char a2 = state[2][j];
        unsigned char a3 = state[3][j];
        state[0][j] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
        state[1][j] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
        state[2][j] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
        state[3][j] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
      }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[i][j] ^= expanded[i][r * 4 + 4 + j];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      ciphertext[j * 4 + i] = state[i][j] ^ key[j * 4 + i];

  return true;
}

static bool aes_128_save_sbox_state(
    const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext,
    std::pair<std::vector<field::GF2E32>, std::vector<field::GF2E32>>
        &saved_sbox_state) {
  unsigned char expanded[4][44];
  unsigned char state[4][4];
  unsigned char newstate[4][4];
  unsigned char roundconstant;
  int i;
  int j;
  int r;

  // make public permutation
  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      expanded[i][j] = plaintext[j * 4 + i];

  roundconstant = 1;
  for (j = 4; j < 44; ++j) {
    unsigned char temp[4], temp2[4];
    if (j % 4)
      for (i = 0; i < 4; ++i)
        temp[i] = expanded[i][j - 1];
    else {
      for (i = 0; i < 4; ++i) {
        temp[i] = expanded[i][j - 1];
      }
      field::GF2E32 s;
      s.from_bytes(temp);
      field::GF2E32 t = s.inverse();
      t.to_bytes(temp2);
      for (i = 0; i < 4; ++i) {
        temp[i] = temp2[(i + 1) % 4];
      }
      temp[0] ^= roundconstant;
      roundconstant = xtime(roundconstant);
    }
    for (i = 0; i < 4; ++i)
      expanded[i][j] = temp[i] ^ expanded[i][j - 4];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      state[i][j] = key[j * 4 + i] ^ expanded[i][j];

  for (r = 0; r < 10; ++r) {
    for (i = 0; i < 4; ++i) {
      std::pair<field::GF2E32, field::GF2E32> sbox_state;
      if (!wordsub_save(&state[i][0], &newstate[i][0], sbox_state))
        return false;
      saved_sbox_state.first.push_back(sbox_state.first);
      saved_sbox_state.second.push_back(sbox_state.second);
    }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[i][j] = newstate[i][(j + i) % 4];
    if (r < 9)
      for (j = 0; j < 4; ++j) {
        unsigned char a0 = state[0][j];
        unsigned char a1 = state[1][j];
        unsigned char a2 = state[2][j];
        unsigned char a3 = state[3][j];
        state[0][j] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
        state[1][j] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
        state[2][j] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
        state[3][j] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
      }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[i][j] ^= expanded[i][r * 4 + 4 + j];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      ciphertext[j * 4 + i] = state[i][j] ^ key[j * 4 + i];

  return true;
}

bool aes_128(const std::vector<uint8_t> &key_in,
             const std::vector<uint8_t> &plaintext_in,
             std::vector<uint8_t> &ciphertext_out) {
  assert(key_in.size() == AES128::KEY_SIZE);
  assert(plaintext_in.size() == AES128::BLOCK_SIZE * AES128::NUM_BLOCKS);
  ciphertext_out.resize(AES128::BLOCK_SIZE * AES128::NUM_BLOCKS);
  return aes_128_old(key_in.data(), plaintext_in.data(), ciphertext_out.data());
}

std::pair<std::vector<field::GF2E32>, std::vector<field::GF2E32>>
aes_128_with_sbox_output(const std::vector<uint8_t> &key_in,
                         const std::vector<uint8_t> &plaintext_in,
                         std::vector<uint8_t> &ciphertext_out) {
  assert(key_in.size() == AES128::KEY_SIZE);
  assert(plaintext_in.size() == AES128::BLOCK_SIZE * AES128::NUM_BLOCKS);
  std::pair<std::vector<field::GF2E32>, std::vector<field::GF2E32>> result;
  result.first.reserve(AES128::NUM_SBOXES);
  result.second.reserve(AES128::NUM_SBOXES);
  ciphertext_out.resize(AES128::BLOCK_SIZE * AES128::NUM_BLOCKS);
  bool ret = aes_128_save_sbox_state(key_in.data(), plaintext_in.data(),
                                     ciphertext_out.data(), result);
  (void)ret;
  assert(ret);
  return result;
}

void aes_128_s_shares(const std::vector<gsl::span<uint8_t>> &key_in,
                      const std::vector<gsl::span<field::GF2E32>> &t_shares,
                      const std::vector<uint8_t> &plaintext_in,
                      std::vector<gsl::span<uint8_t>> &ciphertext_out,
                      std::vector<gsl::span<field::GF2E32>> &s_shares) {

  typedef std::array<std::array<uint8_t, 4>, 4> state_t;
  typedef std::array<uint8_t, 4> temp_t;
  int num_parties = key_in.size();
  unsigned char expanded[4][44];
  std::vector<state_t> state(num_parties);
  std::vector<state_t> newstate(num_parties);
  uint8_t roundconstant;
  int i;
  int j;
  int r;
  int party;
  int sbox_index = 0;
  int first_party = 0;

  // make public permutation
  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      expanded[i][j] = plaintext_in[j * 4 + i];

  roundconstant = 1;
  for (j = 4; j < 44; ++j) {
    unsigned char temp[4], temp2[4];
    if (j % 4)
      for (i = 0; i < 4; ++i)
        temp[i] = expanded[i][j - 1];
    else {
      for (i = 0; i < 4; ++i) {
        temp[i] = expanded[i][j - 1];
      }
      field::GF2E32 s;
      s.from_bytes(temp);
      field::GF2E32 t = s.inverse();
      t.to_bytes(temp2);
      for (i = 0; i < 4; ++i) {
        temp[i] = temp2[(i + 1) % 4];
      }
      temp[0] ^= roundconstant;
      roundconstant = xtime(roundconstant);
    }
    for (i = 0; i < 4; ++i)
      expanded[i][j] = temp[i] ^ expanded[i][j - 4];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i) {
      state[first_party][i][j] =
          key_in[first_party][j * 4 + i] ^ expanded[i][j];
      for (party = 1; party < num_parties; party++) {
        state[party][i][j] = key_in[party][j * 4 + i];
      }
    }

  for (r = 0; r < 10; ++r) {
    for (i = 0; i < 4; ++i) {
      for (party = 0; party < num_parties; party++) {
        field::GF2E32 s;
        s.from_bytes(&state[party][i][0]);
        s_shares[party][sbox_index] = s;
        wordsub_restore(t_shares[party][sbox_index], &newstate[party][i][0]);
      }
      for (j = 0; j < 4; ++j) {
        newstate[first_party][i][j] ^= AES_SBOX_AFFINE_CONST;
      }
      sbox_index++;
    }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        for (party = 0; party < num_parties; party++) {
          state[party][i][j] = newstate[party][i][(j + i) % 4];
        }
    if (r < 9)
      for (j = 0; j < 4; ++j) {
        for (party = 0; party < num_parties; party++) {
          unsigned char a0 = state[party][0][j];
          unsigned char a1 = state[party][1][j];
          unsigned char a2 = state[party][2][j];
          unsigned char a3 = state[party][3][j];
          state[party][0][j] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
          state[party][1][j] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
          state[party][2][j] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
          state[party][3][j] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
        }
      }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[first_party][i][j] ^= expanded[i][r * 4 + 4 + j];
  }

  for (party = 0; party < num_parties; party++) {
    for (j = 0; j < 4; ++j)
      for (i = 0; i < 4; ++i)
        ciphertext_out[party][j * 4 + i] =
            key_in[party][j * 4 + i] ^ state[party][i][j];
  }
}
} // namespace AES128
