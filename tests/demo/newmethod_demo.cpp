//g++ tests/demo/newmethod_demo.cpp -std=c++17 -lstdc++fs -pthread -Wall -Werror -fopenmp  -DOPENFHE_VERSION=1.0.3 -Wno-parentheses -DMATHBACKEND=4 /usr/local/lib/libOPENFHEpke_static.a /usr/local/lib/libOPENFHEcore_static.a -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/ -o demo -O3

#include "../../include/new_psi.h"
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>
#include <cassert>

#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

int main(int argc, char **argv) {

  steady_clock::time_point start, end;

  // max batch size is 65536. If set anything higher -> Error: Modulus size 64 is too large. NativeVectorT supports only modulus size <=  60 bits
  uint32_t batchSize = 8192;
  int sender_vals_size = 100;
  int depth = 6;
  //int ringDimension = batchSize*2;
  int precision = 50;
  int receiver_vals_size = 1;
  unsigned int poly_approx_deg = 13;  // through 8
  const long low_bound = 0;
  const long high_bound = 100; //599754631;

  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetMultiplicativeDepth(depth);
  cout << "Depth: " << depth << endl;
  cout << "Sender size: " << sender_vals_size << endl;
  parameters.SetScalingModSize(precision);
  parameters.SetBatchSize(batchSize);
  parameters.SetPlaintextModulus(536903681);
  //parameters.SetRingDim(ringDimension);
  parameters.SetSecurityLevel(HEStd_128_classic);
  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);
  //cc->Enable(FHE);
  KeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeysGen(keyPair.secretKey);

//  required if rotation operation is needed
/*
  std::vector<int32_t> indexList;
  for (size_t i = 1; i <= batchSize / 2; i <<= 1) {
    indexList.push_back(i);
  }
  cc->EvalRotateKeyGen(keyPair.secretKey, indexList);
*/
// std::vector<uint64_t> sender_vals = {
//       351117013,
//       129149109,
//       728903740,
//       722414292,
//       783408445,
//       661792905,
//       474710867,
//       984891409,
//       242033152,
//       1053663838,
//       290292751,
//       499593362
//   };

  vector<uint64_t> sender_vals;

  std::cout << "sender_vals: " ;
  for (size_t i=1; i<=sender_vals_size; i++){
    sender_vals.push_back(i);
    cout << sender_vals[i-1] << " ";
  }
  cout << endl;

  for (size_t i=1; i<=sender_vals.size(); i++){
    cout << sender_vals[i-1] << " ";
  }

  vector<uint64_t> receiver_vals;
  std::cout << "receiver_vals: " ;
  for (size_t i=1; i<=receiver_vals_size; i++){
    receiver_vals.push_back(1);
    cout << receiver_vals[i-1] << " ";
  }

  assert(sender_vals.size() <= batchSize);

  // cout << "Sender values: ";
  // for (const uint64_t x : sender_vals) {
  //   cout << x << ' ';
  // }
  // cout << endl;

  // cout << "Receiver values: ";
  // for (const uint64_t x : receiver_vals) {
  //   cout << x << ' ';
  // }
  // cout << endl;

  start = steady_clock::now();
  vector<Ciphertext<DCRTPoly>> sender_ctexts = encrypt_batched(sender_vals, cc, keyPair.publicKey);
  end = steady_clock::now();
  long double d = duration_cast<measure_typ>(end - start).count();
  cout << "Sender encryption time: " << d << "ms" << endl;

  start = steady_clock::now();
  Ciphertext<DCRTPoly> receiver_ctexts = encrypt_batched_single(receiver_vals, cc, keyPair.publicKey);
  end = steady_clock::now();
  d = duration_cast<measure_typ>(end - start).count();
  cout << "Receiver encryption time: " << d << "ms" << endl;

  stringstream ss;
  lbcrypto::Serial::Serialize(receiver_ctexts, ss, lbcrypto::SerType::BINARY);
  cout << "Communication per query: " << ss.str().size() << " bytes" << endl;

  cout << "low_bound: " << low_bound << " high_bound: " << high_bound << " Chebyshev degree: " << poly_approx_deg
       << endl;

  start = steady_clock::now();
  auto res = query_sender_batched(sender_ctexts, receiver_ctexts, cc, poly_approx_deg, low_bound, high_bound);
  end = steady_clock::now();
  d = duration_cast<measure_typ>(end - start).count();
  cout << "Homomorphic intersection time: " << d << "ms" << endl;


  lbcrypto::Serial::Serialize(res, ss, lbcrypto::SerType::BINARY);
  std::cout << "Size of result of query: " << ss.str().size() << " bytes";
  std::cout << "\n";

  double final_result = 0.0d;
  Plaintext pt;
  cc->Decrypt(keyPair.secretKey, res, &pt);
  const std::vector<double> &vec_result = pt->GetRealPackedValue();
  cout << "Element-wise results: ";
  for (size_t i = 0; i < sender_vals.size(); i++) {
    cout << vec_result[i] << ' ';
    final_result += vec_result[i];
  }
  cout << endl;

  cout << "Total sum: " << final_result << endl;

  return 0;
}
