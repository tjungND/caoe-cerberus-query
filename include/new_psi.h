#ifndef NEW_PSI
#define NEW_PSI

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <numeric>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include <openfhe.h>
//#include "openfhe.h"

using std::vector;
using namespace lbcrypto;

// TODO probably have to make this much more parameterized - stub for now
double ckks_encode(const uint64_t x) { 
  double ret = (double) x;
  assert(!(ret != ret));
  return ret;
}

vector<Ciphertext<DCRTPoly>>
encrypt_per_element(const vector<uint64_t> &vals,
                    const CryptoContext<DCRTPoly> &cryptoContext,
                    const PublicKey<DCRTPoly> &pk) {
  vector<Ciphertext<DCRTPoly>> ret(vals.size());
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
#ifdef _OPENMP
#pragma omp parallel for
#endif
  for (size_t i = 0; i < vals.size(); i++) {
    vector<double> packed_vals(batchsize, ckks_encode(vals[i]));
    Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(packed_vals);
    ret[i] = cryptoContext->Encrypt(pk, pt);
  }
  return ret;
}

// Single-ciphertext version - more than N/2 inputs will have to be handled by
// another function, or the application
Ciphertext<DCRTPoly>
encrypt_batched_single(const vector<uint64_t> &vals,
                       const CryptoContext<DCRTPoly> &cryptoContext,
                       const PublicKey<DCRTPoly> &pk) {
  if (vals.size() > cryptoContext->GetEncodingParams()->GetBatchSize()) {
    throw std::invalid_argument("Argument larger than batch size!");
  }
  vector<double> packed_vals(vals.size());
#ifdef _OPENMP
#pragma omp parallel for
#endif
  for (size_t i = 0; i < vals.size(); i++) {
    packed_vals[i] = ckks_encode(vals[i]);
  }
  Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(packed_vals);
  return cryptoContext->Encrypt(pk, pt);
}

// encrypt single element: take an element, copy it to all the slots and then
// encrypt that
Ciphertext<DCRTPoly>
encrypt_single_slots(uint64_t &vals,
                     const CryptoContext<DCRTPoly> &cryptoContext,
                     const PublicKey<DCRTPoly> &pk) {

  unsigned int batchSize = cryptoContext->GetEncodingParams()->GetBatchSize();

  std::vector<double> user_input(batchSize, ckks_encode(vals));
  Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(user_input);
  return cryptoContext->Encrypt(pk, pt);
}

// TODO refactor

vector<Plaintext> encode_batched(const vector<uint64_t> &vals,
                                 const CryptoContext<DCRTPoly> &cryptoContext,
                                 const PublicKey<DCRTPoly> &pk) {
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  assert(!(vals.size() % batchsize));
  vector<double> packed_vals;
  packed_vals.reserve(batchsize);
  vector<uint64_t> range;
  range.reserve(batchsize);
  // TODO something better than repeated push_back
  vector<Plaintext> ret;
  for (size_t i = 0; i < vals.size(); i += batchsize) {
    auto end_iter = i + batchsize >= vals.size() ? vals.end()
                                                 : vals.begin() + i + batchsize;
    std::copy(vals.begin() + i, end_iter, std::back_inserter(range));
    packed_vals.clear();
    std::transform(range.begin(), range.end(), std::back_inserter(packed_vals),
                   [](const uint64_t value) { return ckks_encode(value); });
    // Issue: vector too long?
    Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(packed_vals);
    ret.push_back(pt);
  }
  return ret;
}

vector<Ciphertext<DCRTPoly>>
encrypt_batched(const vector<uint64_t> &vals,
                const CryptoContext<DCRTPoly> &cryptoContext,
                const PublicKey<DCRTPoly> &pk) {
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  vector<double> packed_vals;
  packed_vals.reserve(batchsize);
  vector<uint64_t> range;
  range.reserve(batchsize);
  // TODO something better than repeated push_back
  vector<Ciphertext<DCRTPoly>> ret;
  for (size_t i = 0; i < vals.size(); i += batchsize) {
    auto end_iter = i + batchsize >= vals.size() ? vals.end()
                                                 : vals.begin() + i + batchsize;
    std::copy(vals.begin() + i, end_iter, std::back_inserter(range));
    range.resize(batchsize, DUMMY); // Fill with dummy values
    packed_vals.clear();
    std::transform(range.begin(), range.end(), std::back_inserter(packed_vals),
                   [](const uint64_t value) { return ckks_encode(value); });
    // Issue: vector too long?
    Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(packed_vals);
    ret.push_back(cryptoContext->Encrypt(pk, pt));
  }
  return ret;
}

// DEP functions
Ciphertext<DCRTPoly> B(const Ciphertext<DCRTPoly> &y,
                       const CryptoContext<DCRTPoly> &cryptoContext) {
  constexpr double coeff = -4.0 / 27.0;
  auto y2 = cryptoContext->EvalSquare(y);
  auto coeff_y = cryptoContext->EvalMult(y, coeff);
  auto final_y = cryptoContext->EvalMult(y2, coeff_y);
  auto tempC = cryptoContext->EvalAdd(y, final_y);
  return tempC;
}

Ciphertext<DCRTPoly> DEP1(const double L, const double R, const int n,
                          const Ciphertext<DCRTPoly> &x,
                          const CryptoContext<DCRTPoly> &cryptoContext) {
  assert(n >= 1);
  // assert(x <= std::pow(L, n)*R and x >= -(std::pow(L,n)*R));
  auto y = x;
  Ciphertext<DCRTPoly> temp_y;
  for (int i = n - 1; i >= 0; --i) {
    double LtimesR = pow(L, i) * R;
    double invLR = 1.0 / LtimesR;
    auto yMul_invR = cryptoContext->EvalMult(y, invLR);
    temp_y = B(yMul_invR, cryptoContext);
    y = cryptoContext->EvalMult(temp_y, LtimesR);
  }
  return y;
}

// Problem: need to copy or overwrite sender_vals before/during subtraction
// The copy can be done at the application level while reading in input, using
// OpenMP parallel sections
// Swap sender vals and receiver query, if the batching occurs server-side
Ciphertext<DCRTPoly> query(std::vector<Ciphertext<DCRTPoly>> &sender_vals,
                           const Ciphertext<DCRTPoly> &receiver_query,
                           const CryptoContext<DCRTPoly> &cryptoContext,
                           const unsigned int poly_deg, const long low_bound,
                           const long high_bound) {
  assert(0); // This function should not be in use
  assert(low_bound < high_bound);
#pragma omp parallel for
  for (size_t i = 0; i < sender_vals.size(); i++) {
    cryptoContext->EvalSubInPlace(sender_vals.at(i), receiver_query);
    cryptoContext->EvalSquareInPlace(
        sender_vals.at(i)); // only passing +ve input to the chebyshev
    sender_vals.at(i) = cryptoContext->EvalChebyshevFunction(
        [](double x) -> double { return 1 / x; }, sender_vals.at(i), low_bound,
        high_bound, poly_deg);
  }
  return cryptoContext->EvalAddManyInPlace(sender_vals);
}

Ciphertext<DCRTPoly>
query_sender_batched(std::vector<Ciphertext<DCRTPoly>> &sender_vals,
                     const Ciphertext<DCRTPoly> &receiver_query,
                     const CryptoContext<DCRTPoly> &cryptoContext,
                     const unsigned int poly_deg, const long low_bound,
                     const long high_bound
                     , const PrivateKey<DCRTPoly> & sk
                     ) {
  const static bool QUERY_DEBUG = true;                     
  assert(low_bound < high_bound);

  auto derivative_htan_func = [](double x) -> double {
    return (1 - tanh(pow(10.0*x, 2)));
  };
  const double L = 2.58;
  const int n = 6;
  const double R = 34;

  /*
  const double nn = 1;
  const double RR = 57;
  */

  assert(R > 0);
  assert(L > 0);
  assert(n >= 1);

  //DEBUG - take this out for the general case
  assert(sender_vals.size() == 1);

//#pragma omp parallel for
  for (size_t i = 0; i < sender_vals.size(); i++) {

    //DEBUG
    /*
    Plaintext pt;
    cryptoContext->Decrypt(sk, sender_vals[i], &pt);
    cryptoContext->Decrypt(sk, receiver_query, &pt);
    */
    
    if(QUERY_DEBUG){
      cerr << "\t\tComputing query difference...";
    }
    sender_vals[i] = cryptoContext->EvalSub(sender_vals[i], receiver_query);
    if(QUERY_DEBUG){
      cerr << "done.\n\t\tCompressing difference...";
    }
    sender_vals[i] = DEP1(L, R, n, sender_vals[i], cryptoContext);
    if(QUERY_DEBUG){
      cerr << "done.\n\t\tComputing spike function (w/ Chebyshev approximation)...";
    }
    sender_vals[i] = cryptoContext->EvalChebyshevFunction(
        derivative_htan_func, sender_vals[i], -R, R, poly_deg);
    if(QUERY_DEBUG){
      cerr << "done.\n\t\tExaggerating spike...";
    }
     cryptoContext->EvalSquareInPlace(sender_vals[i]); // creating more difference in the zero and non-zero values
     cryptoContext->EvalSquareInPlace(sender_vals[i]);
     cryptoContext->EvalSquareInPlace(sender_vals[i]);
     cryptoContext->EvalSquareInPlace(sender_vals[i]);
     cryptoContext->EvalMultInPlace(sender_vals[i], SPSI_SCALE);
     cryptoContext->EvalSquareInPlace(sender_vals[i]);
     cryptoContext->EvalSquareInPlace(sender_vals[i]);
     cryptoContext->EvalSquareInPlace(sender_vals[i]);
    if(QUERY_DEBUG){
      cerr << "done.\n";
    }

  }
  return cryptoContext->EvalAddManyInPlace(sender_vals);
}

// Probably will have to play around with parametersSender
bool in_intersection(const double query_result) {
  // const static double K_THRESHOLD = 0.75;
  return query_result >= SPSI_THRESHOLD; // Defined in utilities.h
}

vector<int> in_intersection(const Plaintext &pt,
                            const CryptoContext<DCRTPoly> &cryptoContext) {
  vector<int> ret(cryptoContext->GetEncodingParams()->GetBatchSize());
  // This may need to be vector<std::complex<double>>
  const std::vector<double> &vec_result = pt->GetRealPackedValue();
  std:: cerr << "\tMaximum result value: "
         << *max_element(vec_result.begin(), vec_result.end()) << std::endl;
  double accumulated = 0.0;
  for (size_t i = 0; i < ret.size(); i++) {
    assert(!(vec_result[i] != vec_result[i]));
    accumulated += vec_result[i];
    ret[i] = (int)in_intersection(vec_result[i]);
  }
  std::cerr << "\tIntersection Threshold: " << SPSI_THRESHOLD << std::endl;
  return ret;
}

// Some parallelism applicable here
// TODO also restrict number of elements examined
vector<int> in_intersection(const Ciphertext<DCRTPoly> &query_result,
                            const CryptoContext<DCRTPoly> &cryptoContext,
                            const PrivateKey<DCRTPoly> secretKey) {
  Plaintext pt;
  cryptoContext->Decrypt(secretKey, query_result, &pt);
  //cout << "Plaintext: " << pt << endl;
  return in_intersection(pt, cryptoContext);
}

#endif
