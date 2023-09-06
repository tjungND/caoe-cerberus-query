#ifndef NEW_PSI
#define NEW_PSI

#include <cstdint>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include <openfhe.h>
//#include "openfhe.h"

using std::vector;
using namespace lbcrypto;

// TODO probably have to make this much more parameterized - stub for now
double ckks_encode(const uint64_t x) { return (double)x; }

vector<Ciphertext<DCRTPoly>>
sender_encrypt(const vector<uint64_t> &sender_vals,
               const CryptoContext<DCRTPoly> &cryptoContext,
               const PublicKey<DCRTPoly> &pk) {
  vector<Ciphertext<DCRTPoly>> ret(sender_vals.size());
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
#ifdef _OPENMP
#pragma omp parallel for
#endif
  for (size_t i = 0; i < sender_vals.size(); i++) {
    vector<double> packed_vals(batchsize, ckks_encode(sender_vals[i]));
    Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(packed_vals);
    ret[i] = cryptoContext->Encrypt(pk, pt);
  }
  return ret;
}

// Single-ciphertext version - more than N/2 inputs will have to be handled by
// another function, or the application
Ciphertext<DCRTPoly>
receiver_encrypt(const vector<uint64_t> &receiver_vals,
                 const CryptoContext<DCRTPoly> &cryptoContext,
                 const PublicKey<DCRTPoly> &pk) {
  if (receiver_vals.size() >
      cryptoContext->GetEncodingParams()->GetBatchSize()) {
    throw std::invalid_argument("Argument larger than batch size!");
  }
  vector<double> packed_vals(receiver_vals.size());
#ifdef _OPENMP
#pragma omp parallel for
#endif
  for (size_t i = 0; i < receiver_vals.size(); i++) {
    packed_vals[i] = ckks_encode(receiver_vals[i]);
  }
  Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(packed_vals);
  return cryptoContext->Encrypt(pk, pt);
}

// Problem: need to copy or overwrite sender_vals before/during subtraction
// The copy can be done at the application level while reading in input, using
// OpenMP parallel sections
void query_goldschmidt(std::vector<Ciphertext<DCRTPoly>> &sender_vals,
                           const Ciphertext<DCRTPoly> &receiver_query,
                           const CryptoContext<DCRTPoly> &cryptoContext, KeyPair<DCRTPoly> kp) {

      for (size_t i = 0; i < sender_vals.size(); i++) {
    cryptoContext->EvalSubInPlace(sender_vals.at(i), receiver_query);
    }

    Plaintext pt;
  cryptoContext->Decrypt(kp.secretKey, sender_vals[0], &pt);
  const std::vector<double> &vec_result11 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output before query_goldschmidt[" << i
              << "]:" << vec_result11[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[1], &pt);
  const std::vector<double> &vec_result12 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output before query_goldschmidt[" << i
              << "]:" << vec_result12[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[2], &pt);
  const std::vector<double> &vec_result13 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output before query_goldschmidt[" << i
              << "]:" << vec_result13[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[3], &pt);
  const std::vector<double> &vec_result14 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output before query_goldschmidt[" << i
              << "]:" << vec_result14[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[4], &pt);
  const std::vector<double> &vec_result15 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output before query_goldschmidt[" << i
              << "]:" << vec_result15[i] << std::endl;
  }


// actual algorithm: https://link.springer.com/chapter/10.1007/978-3-030-34621-8_15
    std::vector<Ciphertext<DCRTPoly>> a;
    std::vector<Ciphertext<DCRTPoly>> b;
    Ciphertext<DCRTPoly> tempB;
    Ciphertext<DCRTPoly> tempA;

    for (size_t i = 0; i < sender_vals.size(); i++) {
      a.insert(a.begin(), cryptoContext->EvalSub(2, sender_vals.at(i)));
      b.insert(b.begin(), cryptoContext->EvalSub(1, sender_vals.at(i)));
      size_t d = 1;

      for (size_t j= 0; j<= d-1; j++){
        b.insert(b.begin()+j+1, cryptoContext->EvalSquare(b.at(j)));
        tempB = cryptoContext->EvalAdd(1, b.at(j+1));
        tempA = cryptoContext->EvalMult(a.at(j), tempB);
        a.insert(a.begin()+j+1, tempA);
      }
    sender_vals.at(i) = a.at(d);
    sender_vals.at(i) = cryptoContext->EvalSub(4, sender_vals.at(i));
    }


  cryptoContext->Decrypt(kp.secretKey, sender_vals[0], &pt);
  const std::vector<double> &vec_result = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output from query_goldschmidt[" << i
              << "]:" << vec_result[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[1], &pt);
  const std::vector<double> &vec_result1 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output from query_goldschmidt[" << i
              << "]:" << vec_result1[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[2], &pt);
  const std::vector<double> &vec_result2 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output from query_goldschmidt[" << i
              << "]:" << vec_result2[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[3], &pt);
  const std::vector<double> &vec_result3 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output from query_goldschmidt[" << i
              << "]:" << vec_result3[i] << std::endl;
  }

  cryptoContext->Decrypt(kp.secretKey, sender_vals[4], &pt);
  const std::vector<double> &vec_result4 = pt->GetRealPackedValue();

  std::cout << "\n";
  for (size_t i = 0; i < 10; i++) {
    std::cout << "Output from query_goldschmidt[" << i
              << "]:" << vec_result4[i] << std::endl;
  }




}

Ciphertext<DCRTPoly> query(std::vector<Ciphertext<DCRTPoly>> &sender_vals,
                           const Ciphertext<DCRTPoly> &receiver_query,
                           const CryptoContext<DCRTPoly> &cryptoContext,
                           const unsigned int K, const unsigned int S,
                           const unsigned int poly_deg,
                           const long max_item_difference,
                           bool scale_on,
                           KeyPair<DCRTPoly> kp) {
  long bound =
      max_item_difference > 0 ? max_item_difference : -max_item_difference;
  for (size_t i = 0; i < sender_vals.size(); i++) {
    cryptoContext->EvalSubInPlace(sender_vals.at(i), receiver_query);

    sender_vals.at(i) = cryptoContext->EvalChebyshevFunction(
        [](double x) -> double {
        return 1- pow(std::tanh(x),2);
        },
        sender_vals.at(i), 1, 7, poly_deg);
        cryptoContext->EvalSquareInPlace(sender_vals.at(i));
        cryptoContext->EvalMultInPlace(sender_vals.at(i), K);
  }

//   Plaintext pt;
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[0], &pt);
//   const std::vector<double> &vec_result = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result[i] << std::endl;
//   }
//
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[1], &pt);
//   const std::vector<double> &vec_result1 = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result1[i] << std::endl;
//   }
//
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[2], &pt);
//   const std::vector<double> &vec_result2 = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result2[i] << std::endl;
//   }
//
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[3], &pt);
//   const std::vector<double> &vec_result3 = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result3[i] << std::endl;
//   }
//
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[4], &pt);
//   const std::vector<double> &vec_result4 = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result4[i] << std::endl;
//   }
//
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[5], &pt);
//   const std::vector<double> &vec_result5 = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result5[i] << std::endl;
//   }
//
//   cryptoContext->Decrypt(kp.secretKey, sender_vals[6], &pt);
//   const std::vector<double> &vec_result6 = pt->GetRealPackedValue();
//
//   std::cout << "\n";
//   for (size_t i = 0; i < 10; i++) {
//     std::cout << "Output from query[" << i
//               << "]:" << vec_result6[i] << std::endl;
//   }
//
//
//   std::random_device rd;
//   std::mt19937 gen(rd());
//     // Define the range for the distribution
//   double low = 0.0;
//   double high = 1.0;
//   std::uniform_real_distribution<double> dist(low, high);
//   std::cout << "scale interval: " << low << " to " << high << std::endl;
//
//
//   int c_size = sender_vals.size();
//   std::vector<Ciphertext<DCRTPoly>> firstHalf(sender_vals.begin(), std::next(sender_vals.begin(), c_size/2));
//   std::vector<Ciphertext<DCRTPoly>> secondHalf(std::next(sender_vals.begin(), c_size/2), sender_vals.end());
//
//   if (scale_on){
// // scale one half sender_vals by random doubles in the range of 0 to 1
//   for (size_t i = 0; i < secondHalf.size(); i++) {
//     double scale = dist(gen);
//     secondHalf.at(i) = cryptoContext->EvalMult(secondHalf.at(i), scale);
//   }
// std::cout << "\n"<< std::endl;
//   for (size_t i = 0; i < firstHalf.size(); i++) {
//     double scale = dist(gen);
//     firstHalf.at(i) = cryptoContext->EvalMult(firstHalf.at(i), scale);
//   }
// }
//
//   Ciphertext<DCRTPoly> firstSum = cryptoContext->EvalAddManyInPlace(firstHalf);
//   Ciphertext<DCRTPoly> secondSum = cryptoContext->EvalAddManyInPlace(secondHalf);
//
//   cryptoContext->EvalSubInPlace(firstSum, secondSum);
//   return firstSum;

 return cryptoContext->EvalAddManyInPlace(sender_vals);
}

// Probably will have to play around with parametersSender
bool in_intersection(const double query_result, const uint64_t K) {
  const static double K_THRESHOLD = 0.75;
  return query_result >= K_THRESHOLD * K;
}

// Some parallelism applicable here
vector<int> in_intersection(const Ciphertext<DCRTPoly> &query_result,
                            const uint64_t K,
                            const CryptoContext<DCRTPoly> &cryptoContext,
                            const PrivateKey<DCRTPoly> secretKey) {
  Plaintext pt;
  cryptoContext->Decrypt(secretKey, query_result, &pt);
  vector<int> ret(cryptoContext->GetEncodingParams()->GetBatchSize());
  // This may need to be vector<std::complex<double>>
  const std::vector<double> &vec_result = pt->GetRealPackedValue();
  for (size_t i = 0; i < ret.size(); i++) {
    ret[i] = (int)in_intersection(vec_result[i], K);
  }
  return ret;
}

#endif
