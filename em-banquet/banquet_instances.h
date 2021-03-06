/*
 *  This file is part of the optimized implementation of the BANQUET signature
 * scheme. See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef BANQUET_INSTANCES_H
#define BANQUET_INSTANCES_H

#include <cstdint>
#include <cstdlib>

/** Parameter set names */
enum banquet_params_t {
  PARAMETER_SET_INVALID = 0,
  Banquet_L1_Param1 = 1,
  Banquet_L1_Param2 = 2,
  Banquet_L1_Param3 = 3,
  Banquet_L1_Param4 = 4,
  Banquet_L3_Param1 = 5,
  Banquet_L5_Param1 = 6,
  PARAMETER_SET_MAX_INDEX = 7
};

struct banquet_aes_t {
  uint32_t key_size;
  uint32_t block_size;
  uint32_t num_blocks;
  uint32_t num_sboxes;
};

struct banquet_instance_t {

  banquet_aes_t aes_params;

  uint32_t digest_size;     /* bytes */
  uint32_t seed_size;       /* bytes */
  uint32_t num_rounds;      // T
  uint32_t num_MPC_parties; // N

  // m1 * m2 = m (NUM_AES_SBOXES)
  uint32_t m1;     // m1: dimension 1 of sqrt check
  uint32_t m2;     // m2: dimension 2 of sqrt check
  uint32_t lambda; // field expansion factor

  banquet_params_t params;
};

const banquet_instance_t &banquet_instance_get(banquet_params_t param);

#endif
