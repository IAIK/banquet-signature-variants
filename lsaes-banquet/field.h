#pragma once

#include "banquet_instances.h"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <vector>
extern "C" {
#include <smmintrin.h>
#include <wmmintrin.h>
}

namespace field {
class GF2E32;
}

field::GF2E32 dot_product(const std::vector<field::GF2E32> &lhs,
                          const std::vector<field::GF2E32> &rhs);

namespace field {
class GF2E32 {

  uint64_t data;
  // modulus = x^32 + x^7 + x^3 + x^2 + 1
  constexpr static uint64_t modulus =
      (1ULL << 32) | (1ULL << 7) | (1ULL << 3) | (1ULL << 2) | (1ULL << 0);

public:
  constexpr static size_t BYTE_SIZE = 4;

  GF2E32() : data(0){};
  GF2E32(uint64_t data) : data(data) {}
  GF2E32(const GF2E32 &other) = default;
  ~GF2E32() = default;
  GF2E32 &operator=(const GF2E32 &other) = default;

  void clear() { data = 0; }
  void set_coeff(size_t idx) { data |= (1ULL << idx); }
  GF2E32 operator+(const GF2E32 &other) const;
  GF2E32 &operator+=(const GF2E32 &other);
  GF2E32 operator-(const GF2E32 &other) const;
  GF2E32 &operator-=(const GF2E32 &other);
  GF2E32 operator*(const GF2E32 &other) const;
  GF2E32 &operator*=(const GF2E32 &other);
  bool operator==(const GF2E32 &other) const;
  bool operator!=(const GF2E32 &other) const;

  GF2E32 inverse() const;

  void to_bytes(uint8_t *out) const;
  std::array<uint8_t, BYTE_SIZE> to_bytes() const;
  void from_bytes(uint8_t *in);

  friend GF2E32(::dot_product)(const std::vector<field::GF2E32> &lhs,
                               const std::vector<field::GF2E32> &rhs);
};

const GF2E32 &lift_uint8_t(uint8_t value);

std::vector<GF2E32> get_first_n_field_elements(size_t n);
std::vector<std::vector<GF2E32>>
precompute_lagrange_polynomials(const std::vector<GF2E32> &x_values);
std::vector<GF2E32> interpolate_with_precomputation(
    const std::vector<std::vector<GF2E32>> &precomputed_lagrange_polynomials,
    const std::vector<GF2E32> &y_values);

std::vector<GF2E32> build_from_roots(const std::vector<GF2E32> &roots);
GF2E32 eval(const std::vector<GF2E32> &poly, const GF2E32 &point);
} // namespace field

std::vector<field::GF2E32> operator+(const std::vector<field::GF2E32> &lhs,
                                     const std::vector<field::GF2E32> &rhs);
std::vector<field::GF2E32> &operator+=(std::vector<field::GF2E32> &self,
                                       const std::vector<field::GF2E32> &rhs);
std::vector<field::GF2E32> operator*(const std::vector<field::GF2E32> &lhs,
                                     const field::GF2E32 &rhs);
std::vector<field::GF2E32> operator*(const field::GF2E32 &lhs,
                                     const std::vector<field::GF2E32> &rhs);
std::vector<field::GF2E32> operator*(const std::vector<field::GF2E32> &lhs,
                                     const std::vector<field::GF2E32> &rhs);