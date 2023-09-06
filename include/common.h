#ifndef COMMON_H
#define COMMON_H

#include <cstdint>

enum Method { FINITE_FIELD, APPROXIMATE };

const static size_t USER_INPUT_GUESS = 1 << 10;

// TODO Chebyshev defaults, CKKS method K and S parameters

const static uint64_t K_DEFAULT = 1024;
const static uint64_t S_DEFAULT = 16;

#endif