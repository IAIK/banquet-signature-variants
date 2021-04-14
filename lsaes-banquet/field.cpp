#include "field.h"

#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

extern "C" {
#include "portable_endian.h"
}

namespace {
const std::array<field::GF2E32, 256> lifting_lut = [] {
  field::GF2E32 generator;
  std::array<field::GF2E32, 256> lifting_lut;
  lifting_lut[0] = field::GF2E32(0); // lut(0) = 0
  lifting_lut[1] = field::GF2E32(1); // lut(1) = 1
  field::GF2E32 gen;
  gen.set_coeff(30);
  gen.set_coeff(23);
  gen.set_coeff(21);
  gen.set_coeff(18);
  gen.set_coeff(14);
  gen.set_coeff(13);
  gen.set_coeff(11);
  gen.set_coeff(9);
  gen.set_coeff(7);
  gen.set_coeff(6);
  gen.set_coeff(5);
  gen.set_coeff(4);
  gen.set_coeff(3);
  gen.set_coeff(1);

  field::GF2E32 pow = gen;
  for (size_t bit = 1; bit < 8; bit++) {
    size_t start = (1ULL << bit);
    // copy last half of LUT and add current generator power
    for (size_t idx = 0; idx < start; idx++) {
      lifting_lut[start + idx] = lifting_lut[idx] + pow;
    }
    pow = pow * gen;
  }
  return lifting_lut;
}();

inline __m128i clmul(uint64_t a, uint64_t b) {
  return _mm_clmulepi64_si128(_mm_set_epi64x(0, a), _mm_set_epi64x(0, b), 0);
}

// actually a bit slower than naive version below
__attribute__((unused)) uint64_t reduce_GF2_32_barret(__m128i in) {
  // modulus = x^32 + x^7 + x^3 + x^2 + 1
  constexpr uint64_t P =
      (1ULL << 32) | (1ULL << 7) | (1ULL << 3) | (1ULL << 2) | (1ULL << 0);
  constexpr uint64_t mu = P;
  uint64_t R = _mm_cvtsi128_si64(in);
  uint64_t T1 = _mm_cvtsi128_si64(clmul(R >> 32, mu));
  uint64_t T2 = _mm_cvtsi128_si64(clmul(T1 >> 32, P));
  return 0xFFFFFFFFULL & (R ^ T2);
}
inline uint64_t reduce_GF2_32(__m128i in) {
  // modulus = x^32 + x^7 + x^3 + x^2 + 1
  constexpr uint64_t lower_mask = 0xFFFFFFFFULL;
  uint64_t R_lower = _mm_cvtsi128_si64(in);
  uint64_t R_upper = R_lower >> 32;

  uint64_t T = R_upper;
  R_upper = R_upper ^ (T >> 25) ^ (T >> 29) ^ (T >> 30);
  R_lower = R_lower ^ (R_upper << 7) ^ (R_upper << 3) ^ (R_upper << 2) ^
            (R_upper << 0);
  return lower_mask & R_lower;
}

uint64_t GF2_euclidean_div_quotient(uint64_t a, uint64_t b) {
  uint64_t quotient = 0;
  int diff = __builtin_clzl(b) - __builtin_clzl(a);
  while (diff >= 0 && a != 0) {
    quotient |= (1ULL << diff);
    a ^= (b << diff);
    diff = __builtin_clzl(b) - __builtin_clzl(a);
  }
  return quotient;
}

uint64_t mod_inverse(uint64_t a, uint64_t mod) {
  uint64_t t = 0;
  uint64_t new_t = 1;
  uint64_t r = mod;
  uint64_t new_r = a;
  uint64_t tmp;

  while (new_r != 0) {
    uint64_t quotient = GF2_euclidean_div_quotient(r, new_r);
    tmp = r;
    r = new_r;
    new_r = tmp ^ _mm_extract_epi64(clmul(quotient, new_r), 0);
    tmp = t;
    t = new_t;
    new_t = tmp ^ _mm_extract_epi64(clmul(quotient, new_t), 0);
  }

  return t;
}

} // namespace

namespace field {

const GF2E32 &lift_uint8_t(uint8_t value) { return lifting_lut[value]; }

GF2E32 GF2E32::operator+(const GF2E32 &other) const {
  return GF2E32(this->data ^ other.data);
}
GF2E32 &GF2E32::operator+=(const GF2E32 &other) {
  this->data ^= other.data;
  return *this;
}
GF2E32 GF2E32::operator-(const GF2E32 &other) const {
  return GF2E32(this->data ^ other.data);
}
GF2E32 &GF2E32::operator-=(const GF2E32 &other) {
  this->data ^= other.data;
  return *this;
}
GF2E32 GF2E32::operator*(const GF2E32 &other) const {
  return GF2E32(reduce_GF2_32(clmul(this->data, other.data)));
}
GF2E32 &GF2E32::operator*=(const GF2E32 &other) {
  this->data = reduce_GF2_32(clmul(this->data, other.data));
  return *this;
}
bool GF2E32::operator==(const GF2E32 &other) const {
  return this->data == other.data;
}
bool GF2E32::operator!=(const GF2E32 &other) const {
  return this->data != other.data;
}

GF2E32 GF2E32::inverse() const {
  return GF2E32(mod_inverse(this->data, modulus));
}

void GF2E32::to_bytes(uint8_t *out) const {
  uint64_t be_data = htole64(data);
  memcpy(out, (uint8_t *)(&be_data), BYTE_SIZE);
}
std::array<uint8_t, GF2E32::BYTE_SIZE> GF2E32::to_bytes() const {
  std::array<uint8_t, GF2E32::BYTE_SIZE> buffer;
  this->to_bytes(buffer.data());
  return buffer;
}

void GF2E32::from_bytes(uint8_t *in) {
  data = 0;
  memcpy((uint8_t *)(&data), in, BYTE_SIZE);
  data = le64toh(data);
}

std::vector<GF2E32> get_first_n_field_elements(size_t n) {
  std::vector<GF2E32> result;
  result.reserve(n);
  GF2E32 x(2);
  GF2E32 gen = x;
  for (size_t i = 0; i < n; i++) {
    result.push_back(gen);
    gen = gen * x;
  }
  return result;
}

std::vector<std::vector<GF2E32>>
precompute_lagrange_polynomials(const std::vector<GF2E32> &x_values) {
  size_t m = x_values.size();
  std::vector<std::vector<GF2E32>> precomputed_lagrange_polynomials;
  precomputed_lagrange_polynomials.reserve(m);

  std::vector<GF2E32> x_except_k;
  GF2E32 denominator;
  for (size_t k = 0; k < m; k++) {
    denominator = GF2E32(1);
    x_except_k.clear();
    x_except_k.reserve(m - 1);
    for (size_t j = 0; j < m; j++) {
      if (k != j) {
        denominator *= x_values[k] - x_values[j];
        x_except_k.push_back(x_values[j]);
      }
    }
    std::vector<GF2E32> numerator = build_from_roots(x_except_k);

    numerator = numerator * denominator.inverse();
    precomputed_lagrange_polynomials.push_back(numerator);
  }

  return precomputed_lagrange_polynomials;
}

std::vector<GF2E32> interpolate_with_precomputation(
    const std::vector<std::vector<GF2E32>> &precomputed_lagrange_polynomials,
    const std::vector<GF2E32> &y_values) {
  if (precomputed_lagrange_polynomials.size() != y_values.size() ||
      y_values.empty())
    throw std::runtime_error("invalid sizes for interpolation");

  std::vector<GF2E32> res(precomputed_lagrange_polynomials[0].size());
  size_t m = y_values.size();
  for (size_t k = 0; k < m; k++) {
    res += precomputed_lagrange_polynomials[k] * y_values[k];
  }
  return res;
}

std::vector<GF2E32> build_from_roots(const std::vector<GF2E32> &roots) {
  size_t len = roots.size();

  std::vector<GF2E32> poly(roots);
  poly.push_back(GF2E32(0));

  GF2E32 tmp;
  for (size_t k = 1; k < len; k++) {
    tmp = poly[k];
    poly[k] = tmp + poly[k - 1];
    for (size_t i = k - 1; i >= 1; i--) {
      poly[i] = poly[i] * tmp + poly[i - 1];
    }
    poly[0] *= tmp;
  }
  poly[len] = GF2E32(1);
  return poly;
}
// horner eval
GF2E32 eval(const std::vector<GF2E32> &poly, const GF2E32 &point) {
  GF2E32 acc;
  long i;

  for (i = poly.size() - 1; i >= 0; i--) {
    acc *= point;
    acc += poly[i];
  }

  return acc;
}

} // namespace field

std::vector<field::GF2E32> operator+(const std::vector<field::GF2E32> &lhs,
                                     const std::vector<field::GF2E32> &rhs) {
  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  std::vector<field::GF2E32> result(lhs);
  for (size_t i = 0; i < lhs.size(); i++)
    result[i] += rhs[i];

  return result;
}

std::vector<field::GF2E32> &operator+=(std::vector<field::GF2E32> &lhs,
                                       const std::vector<field::GF2E32> &rhs) {
  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  for (size_t i = 0; i < lhs.size(); i++)
    lhs[i] += rhs[i];

  return lhs;
}

// somewhat optimized inner product, only do one lazy reduction
field::GF2E32 dot_product(const std::vector<field::GF2E32> &lhs,
                          const std::vector<field::GF2E32> &rhs) {

  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  // field::GF2E result;
  // for (size_t i = 0; i < lhs.size(); i++)
  // result += lhs[i] * rhs[i];
  __m128i accum = _mm_setzero_si128();
  for (size_t i = 0; i < lhs.size(); i++)
    accum = _mm_xor_si128(accum, clmul(lhs[i].data, rhs[i].data));

  field::GF2E32 result(reduce_GF2_32(accum));
  return result;
}

std::vector<field::GF2E32> operator*(const std::vector<field::GF2E32> &lhs,
                                     const field::GF2E32 &rhs) {
  std::vector<field::GF2E32> result(lhs);
  for (size_t i = 0; i < lhs.size(); i++)
    result[i] *= rhs;

  return result;
}

std::vector<field::GF2E32> operator*(const field::GF2E32 &lhs,
                                     const std::vector<field::GF2E32> &rhs) {
  return rhs * lhs;
}

// naive polynomial multiplication
std::vector<field::GF2E32> operator*(const std::vector<field::GF2E32> &lhs,
                                     const std::vector<field::GF2E32> &rhs) {

  std::vector<field::GF2E32> result(lhs.size() + rhs.size() - 1);
  for (size_t i = 0; i < lhs.size(); i++)
    for (size_t j = 0; j < rhs.size(); j++)
      result[i + j] += lhs[i] * rhs[j];

  return result;
}