#ifndef BINNING_H
#define BINNING_H

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <exception>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include <openfhe.h>

#include "../include/hashing.h"
#include "../include/powers.h"

using std::vector;
using namespace lbcrypto;

using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::Plaintext;

// APSI: figure out how many bins
vector<vector<Plaintext>>
single_sender_bins_APSI(const vector<uint64_t> &sender_data,
                        const unsigned int num_bins, const uint32_t salt,
                        const CryptoContext<DCRTPoly> &cryptoContext,
                        const PublicKey<DCRTPoly> &pk) {}

vector<vector<Ciphertext>>
single_sender_bins_newPSI(const vector<uint64_t> &sender_data,
                          const unsigned int num_bins, const uint32_t salt,
                          const CryptoContext<DCRTPoly> &cryptoContext,
                          const PublicKey<DCRTPoly> &pk) {}

#endif