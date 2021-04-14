/*
 *  This file is part of the optimized implementation of the Picnic signature
 * scheme. See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "banquet_instances.h"

#include <stdexcept>

/* key_size, block_size, num_blocks, num_sboxes */
constexpr banquet_aes_t AES128_PARAMS = {16, 16, 1, 40 /* 160 + 40 */};

static const banquet_instance_t instances[PARAMETER_SET_MAX_INDEX] = {
    {
        {0, 0, 0, 0},
        0,
        0,
        0,
        0,
        0,
        0,
        PARAMETER_SET_INVALID,
    },
    /* AES_params, digest size, seed size, T, N, m1, m2, lambda */
    {AES128_PARAMS, 32, 16, 31, 64, 5, 8, Banquet_L1_Param1},
    {AES128_PARAMS, 32, 16, 31, 64, 8, 5, Banquet_L1_Param2},
};

const banquet_instance_t &banquet_instance_get(banquet_params_t param) {
  if (param <= PARAMETER_SET_INVALID || param >= PARAMETER_SET_MAX_INDEX) {
    throw std::runtime_error("invalid parameter set");
  }

  return instances[param];
}
