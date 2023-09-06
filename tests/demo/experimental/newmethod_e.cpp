#include "new_psi_e.h"
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>
#include <getopt.h>

#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

int main(int argc, char **argv) {

   // Parse command-line arguments
  bool scale_on = false;

  int c;
  while ((c = getopt(argc, argv, "s")) != -1) {
    switch (c) {
    case 's': {
      scale_on = true;
      break;
    }
    default:
      cout << "Invalid argument: " << c << endl;
      return 1;
    }
  }

  steady_clock::time_point start, end;

  uint32_t batchSize = 1024;
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetMultiplicativeDepth(7);
  parameters.SetScalingModSize(50);
  parameters.SetBatchSize(batchSize);
  parameters.SetSecurityLevel(HEStd_128_classic);
  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);
  cc->Enable(FHE);
  KeyPair<DCRTPoly> keyPair = cc->KeyGen();

  cc->EvalMultKeysGen(keyPair.secretKey);

  vector<uint64_t> sender_vals = {1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15};
  //vector<uint64_t> receiver_vals =  {0, 1, 2, 4, 16, 17, 18, 5, 6, 20};
  vector<uint64_t> receiver_vals = {1, 2, 3, 4,  15, 6, 7, 8};
  assert(receiver_vals.size() <= batchSize);

  cout << "Sender values: ";
  for (const uint64_t x : sender_vals) {
    cout << x << ' ';
  }
  cout << endl;

  cout << "Receiver values: ";
  for (const uint64_t x : receiver_vals) {
    cout << x << ' ';
  }
  cout << endl;

  start = steady_clock::now();
  auto sender_ctexts = sender_encrypt(sender_vals, cc, keyPair.publicKey);
  end = steady_clock::now();
  long double d = duration_cast<measure_typ>(end - start).count();
  cout << "Sender encryption time: " << d << "ms" << endl;

  start = steady_clock::now();
  auto receiver_ctexts = receiver_encrypt(receiver_vals, cc, keyPair.publicKey);
  end = steady_clock::now();
  d = duration_cast<measure_typ>(end - start).count();
  cout << "Receiver encryption time: " << d << "ms" << endl;

  stringstream ss;
  lbcrypto::Serial::Serialize(receiver_ctexts, ss, lbcrypto::SerType::BINARY);
  cout << "Communication per query: " << ss.str().size() << " bytes" << endl;

  constexpr unsigned int K = 1 << 14;
  constexpr unsigned int S = 1 << 3;
  unsigned int poly_approx_deg = 5;
  long max_item_difference = 4;

  cout << "S: " << S << " K: " << K << " Chebyshev degree: " << poly_approx_deg << " max item difference: " << max_item_difference << endl;

    std::cout << "\n\n  " << std::endl;
  //query_goldschmidt(sender_ctexts, receiver_ctexts, cc, keyPair);
   std::cout << "\n\n  " << std::endl;


  start = steady_clock::now();
  Ciphertext<DCRTPoly> res = query(sender_ctexts, receiver_ctexts, cc, K, S,
                                   poly_approx_deg, max_item_difference, scale_on, keyPair);
  end = steady_clock::now();
  d = duration_cast<measure_typ>(end - start).count();
  cout << "Homomorphic intersection time: " << d << "ms" << endl;

  double final_result = 0.0d;
  Plaintext pt;
  cc->Decrypt(keyPair.secretKey, res, &pt);
  const std::vector<double> &vec_result = pt->GetRealPackedValue();
  cout << "Element-wise results: ";
  for (size_t i = 0; i < receiver_vals.size(); i++) {
    cout << vec_result[i] << ' ';
    final_result += vec_result[i];
  }
  cout << endl;

  cout << "Total sum: " << final_result << endl;

  return 0;
}
