#ifndef BASIC_PSI_H
#define BASIC_PSI_H

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

#include "../include/powers.h"
#include "../include/utilities.h"

using std::vector;
using namespace lbcrypto;

using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::Plaintext;

typedef __int128 int128_t;

// TODO accelerate with #pragma omp parallel sections

vector<uint64_t> sender_polynomial(const vector<uint64_t> &sender_vals,
                                   const uint128_t modulus) {
  vector<uint64_t> poly(sender_vals.size() + 1, 0);
  vector<uint64_t> shift_poly(sender_vals.size() + 1, 0);
  poly[0] = 1;
  shift_poly[0] = 1;
  size_t terms = 0;
  for (const uint64_t &a : sender_vals) {
    terms++;
    // First, multiply the existing polynomial by x, i.e., shift each
    // coefficient by 1
#ifdef _OPENMP
#pragma omp parallel sections
    { // Start sections
#pragma omp section
      { // Start first section
#endif
        // Lazy slow way to shift...
        std::rotate(shift_poly.rbegin(), shift_poly.rbegin() + 1,
                    shift_poly.rend());
#ifdef _OPENMP
      } // End first section
#pragma omp section
      { // Start second section
#endif
        //  Also, multiply by -a
        uint128_t neg_a = (modulus - a);
        if (a) {
          for (size_t i = 0; i < terms; i++) {
            uint128_t tmp = neg_a * poly[i];
            tmp %= modulus;
            poly[i] = tmp;
          }
        }
#ifdef _OPENMP
      } // End second section
    }   // End sections
#endif
    // Now, add the shifted and multiplied polynomials, writing results to
    // both
#pragma omp parallel for
    for (size_t i = 0; i <= terms; i++) {
      uint64_t tmp;
      if (a) {
        tmp = (poly[i] + shift_poly[i]) % modulus;
      } else {
        tmp = shift_poly[i];
      }
      poly[i] = tmp;
      shift_poly[i] = tmp;
    }
  }
  return poly;
}

std::vector<std::vector<uint64_t>>
splitVector(const std::vector<uint64_t> &inputVector,
            const unsigned int numBins, size_t &max_size) {
  std::vector<std::vector<uint64_t>> result;
  result.reserve(numBins);
  int size = inputVector.size();
  int batchSize = (size + numBins - 1) / numBins;
  max_size = 0;
  for (int i = 0; i < size; i += batchSize) {
    std::vector<uint64_t> bin(inputVector.begin() + i,
                              inputVector.begin() +
                                  std::min(i + batchSize, size));
    max_size = std::max(max_size, bin.size());
    result.push_back(bin);
  }
  return result;
}

// Given a SINGLE BATCH of elements, construct a sender polynomial
// TODO rewrite, this is very inefficient
vector<vector<int64_t>> sender_polynomial_batched(
    const vector<uint64_t> &sender_vals,
    const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext,
    unsigned int &slots_used) {
  uint64_t plain_modulus =
      cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
  size_t batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  assert(sender_vals.size());
  assert(batchsize);

  unsigned int slots_to_use = std::min(batchsize, sender_vals.size());

  // Split the input
  size_t max_size = 0;
  vector<vector<uint64_t>> slot_elts =
      splitVector(sender_vals, slots_to_use, max_size);

  slots_used = slot_elts.size();

  unsigned int num_poly_coeffs = max_size + 1;

  vector<vector<int64_t>> batched_polynomials_coeffwise(
      num_poly_coeffs); //(x-a) for 1 value; k+1 coefficients for k values
                        //#pragma omp parallel for
  for (size_t i = 0; i < batched_polynomials_coeffwise.size(); i++) {
    batched_polynomials_coeffwise[i].resize(batchsize, 0);
  }

  for (size_t i = 0; i < slot_elts.size(); i++) {
    // std::cerr << "slot i: " << i << std::endl;
    vector<uint64_t> poly_this_coeff =
        sender_polynomial(slot_elts[i], plain_modulus);
    assert(poly_this_coeff.size() <= num_poly_coeffs);

    for (size_t j = 0; j < poly_this_coeff.size(); j++) {
      batched_polynomials_coeffwise.at(j).at(i) =
          (int64_t)poly_this_coeff.at(j);
    }
    // assert(i != 16384-1);
  }

  return batched_polynomials_coeffwise;
}

vector<Plaintext> sender_polynomial_batched_plaintexts(
    const vector<uint64_t> &sender_vals,
    const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext,
    unsigned int &slots_used) {
  vector<vector<int64_t>> plain_by_coeff =
      sender_polynomial_batched(sender_vals, cryptoContext, slots_used);

  vector<Plaintext> ret(plain_by_coeff.size());
  for (size_t i = 0; i < ret.size(); i++) {
    ret[i] = cryptoContext->MakePackedPlaintext(plain_by_coeff[i]);
  }
  return ret;
}

vector<Plaintext>
sender_polynomial(const vector<uint64_t> &sender_vals,
                  const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext) {
  vector<Plaintext> ret(sender_vals.size() + 1);
  uint64_t plain_modulus =
      cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  vector<uint64_t> sender_poly_coeffs =
      sender_polynomial(sender_vals, plain_modulus);
#ifdef _OPENMP
#pragma omp parallel for
#endif
  for (size_t i = 0; i < ret.size(); i++) {
    vector<int64_t> v(batchsize, sender_poly_coeffs[i]);
    ret[i] = cryptoContext->MakePackedPlaintext(v);
  }
  return ret;
}

vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>>
receiver_windowed_vals(const vector<uint64_t> &receiver_vals,
                       std::set<unsigned int> &window_sources,
                       const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext,
                       const PublicKey<DCRTPoly> &pk) {
  if (window_sources.find(1) == window_sources.end()) {
    throw std::invalid_argument("Windowing source values must include 1");
  }
  if (receiver_vals.size() >
      cryptoContext->GetEncodingParams()->GetBatchSize()) {
    std::string err =
        "window_sources size: " + std::to_string(window_sources.size()) +
        " batchsize: " +
        std::to_string(cryptoContext->GetEncodingParams()->GetBatchSize());
    throw std::invalid_argument(err);
  }
  // Silently remove 0
  if (window_sources.find(0) != window_sources.end()) {
    window_sources.erase(0);
  }

  // Plaintext modulus
  uint64_t plain_modulus =
      cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

  unsigned int max_power =
      *(window_sources
            .rbegin()); // Insert the Homer Simpson joke of your choosing
  vector<int64_t> powers(receiver_vals.size());
  // This loop can be parallelized
  for (size_t i = 0; i < powers.size(); i++) {
    assert(receiver_vals[i]);
    powers[i] = ((receiver_vals[i] % plain_modulus) + plain_modulus) %
                plain_modulus; // Force to positive representation
    assert(powers[i]);
  }
  vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>> ret;
  ret.reserve(window_sources.size());

  // There's a way of doing this with much fewer multiplications, but we'll put
  // that in later
  Plaintext pt;
  for (unsigned int i = 1; i <= max_power; i++) {
    if (window_sources.find(i) != window_sources.end()) {
      pt = cryptoContext->MakePackedPlaintext(powers);
      ret.emplace_back(i, cryptoContext->Encrypt(pk, pt));
    }
    if (i != max_power) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
      for (size_t j = 0; j < receiver_vals.size(); j++) {
        uint128_t tmp = powers[j];
        tmp *= receiver_vals[j];
        tmp = ((tmp % plain_modulus) + plain_modulus) %
              plain_modulus; // Again force correct positive modulus
        powers[j] = tmp;
      }
    }
  }
  return ret;
}

// Returns set for debugging
std::set<unsigned int>
compute_all_powers(const PowersDag &dag,
                   std::vector<Ciphertext<DCRTPoly>> &powers,
                   const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext) {
  std::set<unsigned int> ret;
  // Change this to parallel_apply later?
  dag.parallel_apply([&](const PowersDag::PowersNode &node) {
    if (!node.is_source()) {
      auto parents = node.parents;
      assert(parents.first);
      assert(parents.second);
      assert(parents.first <= powers.size());
      assert(parents.second <= powers.size());

      if (parents.first == parents.second) {
        powers[node.power - 1] =
            cryptoContext->EvalSquare(powers[parents.first - 1]);
      } else {
        powers[node.power - 1] = cryptoContext->EvalMult(
            powers[parents.first - 1], powers[parents.second - 1]);
      }
      ret.insert(parents.first);
      ret.insert(parents.second);
      ret.insert(node.power);
    }
  });
  return ret;
}

Ciphertext<DCRTPoly>
eval_sender_poly_dot(std::vector<Ciphertext<DCRTPoly>> &powers,
                     const vector<Plaintext> &sender_poly,
                     const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext) {
  if (sender_poly.empty() || (powers.size() + 1) != sender_poly.size()) {
    throw std::invalid_argument("Powers and sender polynomial length mismatch");
  }

  // First, multiply each power with the corresponding sender coefficient
#if _OPENMP
#pragma omp parallel for
#endif
  for (size_t i = 0; i < powers.size(); i++) {
    // Inplace operations not implemented
    powers[i] = cryptoContext->EvalMult(powers[i], sender_poly[i + 1]);
  }
  // Then, sum them all up to a single ciphertext
  auto ret = cryptoContext->EvalAddManyInPlace(powers);
  // Add the constant coefficient
  cryptoContext->EvalAddInPlace(ret, sender_poly[0]);
  return ret;
}

Ciphertext<DCRTPoly> eval_sender_poly_PS(
    std::vector<Ciphertext<DCRTPoly>> &powers,
    const vector<Plaintext> &sender_poly,
    const lbcrypto::CryptoContext<DCRTPoly> &cryptoContext,
    const unsigned int ps_low_degree) { // ps_low_degree should equal to L-1
  size_t degree = sender_poly.size() - 1;
  if (ps_low_degree <= 1 || ps_low_degree >= degree) {
    throw invalid_argument(
        "ps_low_degree must be greater than 1 and less than the "
        "size of batched_coeffs");
  }

  unsigned int ps_high_degree = ps_low_degree + 1;
  unsigned int ps_high_degree_powers = degree / ps_high_degree;
  Ciphertext<DCRTPoly> result, temp, temp_in;
  // Plaintext coeff;
  // First loops
  //  Calculate polynomial for i=1,...,ps_high_degree_powers-1
  for (unsigned int i = 1; i < ps_high_degree_powers; i++) {
    // Evaluate inner polynomial. The free term is left out and added later on.
    // The evaluation result is stored in temp_in.
    for (unsigned int j = 1; j < ps_high_degree; j++) {
      if (j == 1) {
        temp_in = cryptoContext->EvalMult(
            powers.at(j - 1), sender_poly.at(i * ps_high_degree + j));
      } else {
        temp = cryptoContext->EvalMult(powers.at(j - 1),
                                       sender_poly.at(i * ps_high_degree + j));
        cryptoContext->EvalAddInPlace(temp_in, temp);
      }
    }
    if (i == 1) {
      result = cryptoContext->EvalMult(
          temp_in,
          powers.at(i * ps_high_degree - 1)); // only some Initialization
    } else {
      temp_in =
          cryptoContext->EvalMult(temp_in, powers.at(i * ps_high_degree - 1));
      cryptoContext->EvalAddInPlace(result, temp_in);
    }

  } // End first loops

  // Second loops
  //  Calculate polynomial for i=ps_high_degree_powers.
  if (degree % ps_high_degree > 0) {
    for (unsigned int j = 1; j <= degree % ps_high_degree; j++) {
      if (j == 1) {
        temp_in = cryptoContext->EvalMult(
            powers.at(j - 1),
            sender_poly.at(ps_high_degree_powers * ps_high_degree + j));
      } else {
        temp = cryptoContext->EvalMult(
            powers.at(j - 1),
            sender_poly.at(ps_high_degree_powers * ps_high_degree + j));
        cryptoContext->EvalAddInPlace(temp_in, temp);
      }
    }
    temp_in = cryptoContext->EvalMult(
        temp_in, powers.at(ps_high_degree * ps_high_degree_powers - 1));
    cryptoContext->EvalAddInPlace(result, temp_in);
  } // End second loops

  // Third loop
  // Calculate inner polynomial for i=0.
  for (unsigned int j = 1; j < ps_high_degree; j++) {
    temp = cryptoContext->EvalMult(
        powers.at(j - 1),
        sender_poly.at(
            j)); // https://github.com/microsoft/APSI/blob/95ff2cbad3e523e3788a5f8e4baf4638fbf0c6c7/sender/apsi/bin_bundle.cpp#L323
    cryptoContext->EvalAddInPlace(result, temp);
  }

  // Fourth loop
  // Add constant coeffs
  for (unsigned int i = 1; i < ps_high_degree_powers + 1; i++) {
    temp = cryptoContext->EvalMult(powers.at(i * ps_high_degree - 1),
                                   sender_poly.at(i * ps_high_degree));
    cryptoContext->EvalAddInPlace(result, temp);
  }

  // Add constant coefficient
  cryptoContext->EvalAddInPlace(result, sender_poly.at(0));

  return result;
}

vector<int> finite_field_result(const Plaintext &pt,
                                const CryptoContext<DCRTPoly> &cryptoContext,
                                const unsigned int num_elts) {
  const vector<int64_t> &dec = pt->GetPackedValue();
  size_t batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  size_t result_bound =
      num_elts ? std::min((size_t)num_elts, batchsize) : batchsize;
  vector<int> ret(result_bound);
  for (size_t i = 0; i < result_bound; i++) {
    ret[i] = (dec[i] == 0);
  }
  return ret;
}

vector<int> finite_field_result(const Ciphertext<DCRTPoly> &res,
                                const CryptoContext<DCRTPoly> &cryptoContext,
                                const PrivateKey<DCRTPoly> secretKey,
                                const unsigned int num_elts) {
  Plaintext pt;
  cryptoContext->Decrypt(secretKey, res, &pt);
  // std::cout<< "plaintext length: " << pt->GetLength() << std::endl;
  return finite_field_result(pt, cryptoContext, num_elts);
}

#endif
