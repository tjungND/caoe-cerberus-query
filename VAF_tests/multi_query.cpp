// g++ -std=c++17 -o multi_query multi_query.cpp -DOPENFHE_VERSION=1.0.3 -Wno-parentheses -DMATHBACKEND=4 -Wl,-rpath,/usr/local/lib/ /usr/local/lib/libOPENFHEcore.so /usr/local/lib/libOPENFHEpke.so /usr/local/lib/libOPENFHEpke_static.a /usr/local/lib/libOPENFHEcore_static.a -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/ -lstdc++fs -O3 -fopenmp

// This code implements parallelism for evaluating multi-query PSMT ciphertexts

#include "openfhe.h"
#include <cmath>
#include <ctime>
#include <cassert>
#include <omp.h>
#include <numeric> // For std::iota

#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <thread>


using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;


void EvalFunctionExample();

auto derivative_htan_func = [](double x) -> double { return (1 - tanh(pow(10.0 * x, 2))); };

void printFirst20Values(const std::vector<double>& vec) {
    std::cout << "First 20 values of vec_result2:" << std::endl;
    std::cout << std::fixed << std::setprecision(2); // set precision for double values
    size_t count = 0;
    for (size_t i = 0; i < vec.size() && count < 20; ++i) {
        std::cout << "Value " << (i + 1) << ": " << vec[i] << std::endl;
        ++count;
    }
}

std::vector<double> generateRandomNonZeroValues(int size, double min_val, double max_val) {
    std::vector<double> result;

    if (size <= 0) {
        return result; // Return an empty vector if the size is not positive
    }

    if (min_val >= max_val || min_val >= 0.0 || max_val <= 0.0) {
        return result; // Return an empty vector if the range is invalid or does not contain non-zero values
    }

    std::random_device rd;
    std::mt19937 gen(rd());

    // Set the minimum value of the distribution to be 5 units away from 0 in either direction
    std::uniform_real_distribution<double> dis((min_val > 0.0) ? std::max(5.0, min_val) : std::min(-5.0, min_val),
                                               (max_val < 0.0) ? std::min(-5.0, max_val) : std::max(5.0, max_val));

    result.reserve(size);

    // Fill the vector with random non-zero values excluding the range between -5 and 5
    for (int i = 0; i < size; ++i) {
        double random_val = dis(gen);
        result.push_back(random_val);
    }

    return result;
}


 Ciphertext<DCRTPoly> B(const Ciphertext<DCRTPoly> &y, const CryptoContext<DCRTPoly> &cryptoContext){
   constexpr double coeff = -4.0/27.0;
   auto y2 = cryptoContext->EvalSquare(y);
   auto coeff_y = cryptoContext->EvalMult(y, coeff);
   auto final_y = cryptoContext->EvalMult(y2, coeff_y);

   auto tempC = cryptoContext->EvalAdd(y, final_y);

  return tempC;

 }

Ciphertext<DCRTPoly>
DEP1(const double L, const double R, const int n,
                  const Ciphertext<DCRTPoly> &x,
                  const CryptoContext<DCRTPoly> &cryptoContext) {
   assert(n >= 1);
   //assert(x <= std::pow(L, n)*R and x >= -(std::pow(L,n)*R));

   auto y = x;
   Ciphertext<DCRTPoly> temp_y;
   for (int i=n-1; i>=0; --i){

     double LtimesR = pow(L,i) * R;
     double invLR = 1.0 / LtimesR;
     auto yMul_invR = cryptoContext->EvalMult(y, invLR);
     temp_y = B(yMul_invR, cryptoContext);
     y = cryptoContext->EvalMult(temp_y, LtimesR);

   }

   return y;

}

//     // algorithm 2 has higher number of homomorphic evaluations than algorithm 1 for DEP. We stick to using algorithm 1 for now

// Ciphertext<DCRTPoly>
// DEP2(const double L, const double R, const int n,
//                   const Ciphertext<DCRTPoly> &x,
//                   const CryptoContext<DCRTPoly> &cryptoContext) {
//    assert(n >= 1);
//    //assert(x <= std::pow(L, n)*R and x >= -(std::pow(L,n)*R));
//
//    double y = x;
//
//     for (int i = n - 1; i >= 0; --i) {
//         assert(i >= 0);
//         auto y2 = cryptoContext->EvalSquare(y);
//         auto y3 = cryptoContext->EvalMult(y, y2);
//         auto temp_y = cryptoContext->EvalMult((4.0 / (R * R * 27 * pow(L, 2 * i))), y3);
//         cryptoContext->EvalSubInPlace(y, temp_y);
//     }
//
//     cryptoContext->EvalMultInPlace(y, 1/R);
//
//     y /= R;
//     y += (4.0 / 27.0) * ((L * L * (pow(L, n * 2) - 1)) / ((L * L - 1) * pow(L, 2 * n))) * (pow(y, 3) - pow(y, 5));
//     return P(R * y);
//
//    return y;
//
// }

void processQuery(const double L, const double R, const int n, Ciphertext<DCRTPoly>& result_temp,
                  CryptoContext<DCRTPoly> cc, size_t j, size_t k, double low_bound, double high_bound, size_t poly_approx_deg) {
    result_temp = DEP1(L, R, n, result_temp, cc);
    result_temp = cc->EvalChebyshevFunction(derivative_htan_func, result_temp, low_bound, high_bound, poly_approx_deg);

    for (size_t m = 0; m < j; m++) {
        cc->EvalSquareInPlace(result_temp);
    }
    cc->EvalMultInPlace(result_temp, 2.7);
    for (size_t m = 0; m < k; m++) {
        cc->EvalSquareInPlace(result_temp);
    }

   // std::cout << "Number of levels remaining after chebyshev: " << multDepth - result_temp->GetLevel() << std::endl;
}



int main(int argc, char* argv[]) {
    EvalFunctionExample();
    return 0;
}


void EvalFunctionExample() {
    size_t numQueryVectors;
    std::cout << "Enter the number of query vectors to process: ";
    std::cin >> numQueryVectors;
      // Change this variable to control the number of query vectors -> checked and works for upto 128
    std::cout << "--------------------------------- EVAL DEP CHEBYSHEV FUNCTION for "<< numQueryVectors << " receiver elements ---------------------------------"
              << std::endl;
              steady_clock::time_point start, end;
              start = steady_clock::now();

              steady_clock::time_point start_cc, end_cc;
              start_cc = steady_clock::now();

    CCParams<CryptoContextCKKSRNS> parameters;


    //parameters.SetRingDim(1 << 15);

    double L = 2.58;//2.598076211;
    int n = 7;
    double R = 43.5;

    uint32_t multDepth = 45; // 24 depth need for L=2.5, n=6, R=20 for DEP, then for deg 13 Cheby add another 6 dedpth. To square after Cheby add more
    unsigned int poly_approx_deg = 27;
    //uint32_t batchSize = 16;

    double low_bound = -R;
    double high_bound = R;
    int setSize = 32768;

    #if NATIVEINT == 128 
     std::cout << "Running CKKS in 128-bit mode." << std::endl;
    #else
     std::cout << "Running CKKS in 64-bit mode." << std::endl;
    #endif
    /////  
    
    parameters.SetMultiplicativeDepth(multDepth);

    parameters.SetExecutionMode(EXEC_EVALUATION);
    
    parameters.SetRingDim(1 << 16);
   // parameters.SetScalingModSize(45);


    
    int alpha = 1024;
    int s = 30;
    parameters.SetNumAdversarialQueries(alpha);
    parameters.SetStatisticalSecurity(s);
 
    // sigma (noise bits) = underroot(24 * N * alpha) * 2^(s/2), N is the ring-dimension of RLWE
    double noise = 30;  // originally 34, highest 42
    parameters.SetNoiseEstimate(noise);
    parameters.SetSecurityLevel(HEStd_128_classic);

    // We can set our desired precision for 128-bit CKKS only. For NATIVE_SIZE=64, we ignore this parameter.
    // parameters.SetDesiredPrecision(10);
    parameters.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);


    parameters.SetScalingModSize(45);
    parameters.SetBatchSize(32768);
    


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    // We need to enable Advanced SHE to use the Chebyshev approximation.
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);


    std::cerr << "CKKS parameters :::::::: " << parameters << std::endl;
    std::cerr << std::endl;

    std::cerr << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cerr << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cerr << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    usint cyclOrder = cc->GetCyclotomicOrder();


    unsigned int batchSize = cc->GetEncodingParams()->GetBatchSize();
    std::cout << "batchSize: " << batchSize << std::endl;
    std::vector<int> indexList;
    for (size_t i = 1; i <= batchSize / 2; i <<= 1) {
            indexList.push_back(i);
          }

    auto keyPair = cc->KeyGen();
          // We need to generate mult keys to run Chebyshev approximations.
    cc->EvalMultKeyGen(keyPair.secretKey);
    auto pk = keyPair.publicKey;

    cc->EvalRotateKeyGen(keyPair.secretKey, indexList);

    end_cc = steady_clock::now();


    //std::cout << "parameters: " << parameters << std::endl;

    std::cout << "Range is +-" << R * std::pow(L, n) << std::endl;

    std::cout << "scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    std::cout << "ring dimension: " << cc->GetRingDimension() << std::endl;
    std::cout << "noise estimate: " << parameters.GetNoiseEstimate() << std::endl;
    std::cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() << std::endl;
    std::cout << "polynomial approx degree for chebyshev: " << poly_approx_deg << std::endl;

    std::cout << "Noise level: " << parameters.GetNoiseEstimate() << std::endl;

/*
     std::vector<double> test_vals;
    test_vals.reserve(2 * setSize); // Reserve enough space to avoid reallocations

    // Generate values from -setSize to -1
    std::vector<double> negative_vals(setSize);
    std::iota(negative_vals.begin(), negative_vals.end(), -static_cast<double>(setSize));
    test_vals.insert(test_vals.end(), negative_vals.begin(), negative_vals.end());

    // Generate values from 1 to setSize
    std::vector<double> positive_vals(setSize);
    std::iota(positive_vals.begin(), positive_vals.end(), 1.0);
    test_vals.insert(test_vals.end(), positive_vals.begin(), positive_vals.end());

    // Shuffle the elements randomly
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(test_vals.begin(), test_vals.end(), g);

    // Resize the test_vals to batchSize - numQueryVectors, keeping the first (batchSize - numQueryVectors) elements
    if (test_vals.size() > batchSize - numQueryVectors) {
        test_vals.resize(batchSize - numQueryVectors);
    }

    // Add values from 1 to numQueryVectors
    for (size_t i = 0; i < numQueryVectors; ++i) {
        test_vals.push_back(i + 1);
    }
*/

// NEW IDEA CODE BEGINS:

std::vector<double> query_vec(batchSize);

// Fill the first numQueryVectors elements with values from 1 to numQueryVectors
std::iota(query_vec.begin(), query_vec.begin() + numQueryVectors, 1.0);

// Fill the remaining elements with 0
std::fill(query_vec.begin() + numQueryVectors, query_vec.end(), 0.0);

Ciphertext<DCRTPoly> query_ctext;
Plaintext pt4 = cc->MakeCKKSPackedPlaintext(query_vec);
query_ctext = cc->Encrypt(pk, pt4);


std::vector<Plaintext> oneHotPlaintexts(numQueryVectors);
std::vector<Ciphertext<DCRTPoly>> queryCiphertexts(numQueryVectors);
std::vector<Ciphertext<DCRTPoly>> results(numQueryVectors);

std::vector<double> oneHot(batchSize, 0);
Ciphertext<DCRTPoly> ct_temp;

for (size_t i = 0; i < numQueryVectors; ++i) {
    std::fill(oneHot.begin(), oneHot.end(), 0);
    oneHot[i] = 1;
    oneHotPlaintexts[i] = cc->MakeCKKSPackedPlaintext(oneHot);

    // Compute the query ciphertext for the current one-hot plaintext
    queryCiphertexts[i] = cc->EvalMult(query_ctext, oneHotPlaintexts[i]);
    for (size_t j = 1; j <= batchSize / 2; j <<= 1) {
        ct_temp = cc->EvalRotate(queryCiphertexts[i], j);
        cc->EvalAddInPlace(queryCiphertexts[i], ct_temp);
    }
}

// Prepare the sender vector and ciphertext
std::vector<double> sender_vec;
for (double i = 1; i <= batchSize; ++i) {
    sender_vec.push_back(i);
}

// this should be changed to test_vals 
Plaintext pt3 = cc->MakeCKKSPackedPlaintext(sender_vec);
Ciphertext<DCRTPoly> sender_ctext = cc->Encrypt(pk, pt3);

// Compute the results
for (size_t i = 0; i < numQueryVectors; ++i) {
    results[i] = cc->EvalSub(sender_ctext, queryCiphertexts[i]);
}

// Now you have results from results[0] to results[numQueryVectors - 1]



/*
Ciphertext<DCRTPoly> query_ctext;
Plaintext pt4 = cc->MakeCKKSPackedPlaintext(query_vec);
query_ctext = cc->Encrypt(pk, pt4);

// creating one hot vectors

for (size_t i=0; i<num_queries; i++){

  std::vector<double> oneHot_i(batchSize, 0);
oneHot_i[i] = 1;
Plaintext pt_oneHot_i = cc->MakeCKKSPackedPlaintext(oneHot_i);

}


std::vector<double> oneHot_0(batchSize, 0);
oneHot_0[0] = 1;
Plaintext pt_oneHot_0 = cc->MakeCKKSPackedPlaintext(oneHot_0);


std::vector<double> oneHot_1(batchSize, 0);
oneHot_1[1] = 1;
Plaintext pt_oneHot_1 = cc->MakeCKKSPackedPlaintext(oneHot_1);

std::vector<double> oneHot_2(batchSize, 0);
oneHot_2[2] = 1;
Plaintext pt_oneHot_2 = cc->MakeCKKSPackedPlaintext(oneHot_2);

std::vector<double> oneHot_3(batchSize, 0);
oneHot_3[3] = 1;
Plaintext pt_oneHot_3 = cc->MakeCKKSPackedPlaintext(oneHot_3);


// getting the first query value and creating replicas
Ciphertext<DCRTPoly> ct_temp;


Ciphertext<DCRTPoly> query_ctxt_oneHot_0 = cc->EvalMult(query_ctext, pt_oneHot_0);
for (size_t i = 1; i <= batchSize / 2; i <<= 1) {
        ct_temp = cc->EvalRotate(query_ctxt_oneHot_0, i);
        cc->EvalAddInPlace(query_ctxt_oneHot_0, ct_temp);
      }


// getting the second query value
Ciphertext<DCRTPoly> query_ctxt_oneHot_1 = cc->EvalMult(query_ctext, pt_oneHot_1);
for (size_t i = 1; i <= batchSize / 2; i <<= 1) {
        ct_temp = cc->EvalRotate(query_ctxt_oneHot_1, i);
        cc->EvalAddInPlace(query_ctxt_oneHot_1, ct_temp);
      }

// getting the third query value
Ciphertext<DCRTPoly> query_ctxt_oneHot_2 = cc->EvalMult(query_ctext, pt_oneHot_2);
for (size_t i = 1; i <= batchSize / 2; i <<= 1) {
        ct_temp = cc->EvalRotate(query_ctxt_oneHot_2, i);
        cc->EvalAddInPlace(query_ctxt_oneHot_2, ct_temp);
      }

// getting the fourth query value
Ciphertext<DCRTPoly> query_ctxt_oneHot_3 = cc->EvalMult(query_ctext, pt_oneHot_3);
for (size_t i = 1; i <= batchSize / 2; i <<= 1) {
        ct_temp = cc->EvalRotate(query_ctxt_oneHot_3, i);
        cc->EvalAddInPlace(query_ctxt_oneHot_3, ct_temp);
      }


      std::vector<double> sender_vec;

      for (double i = 1; i <= batchSize; ++i) {
          sender_vec.push_back(i);
      }
    Ciphertext<DCRTPoly> sender_ctext;
    //Ciphertext<DCRTPoly> test_ctext2;
    Plaintext pt3 = cc->MakeCKKSPackedPlaintext(sender_vec);
    sender_ctext = cc->Encrypt(pk, pt3);


    Ciphertext<DCRTPoly> result_0;
    result_0 = cc->EvalSub(sender_ctext, query_ctxt_oneHot_0);

    Ciphertext<DCRTPoly> result_1;
    result_1 = cc->EvalSub(sender_ctext, query_ctxt_oneHot_1);

        Ciphertext<DCRTPoly> result_2;
    result_2 = cc->EvalSub(sender_ctext, query_ctxt_oneHot_2);

        Ciphertext<DCRTPoly> result_3;
    result_3 = cc->EvalSub(sender_ctext, query_ctxt_oneHot_3);


// new idea ends

*/

    //Plaintext pt4 = cc->MakeCKKSPackedPlaintext(test_vals2);
    //test_ctext2 = cc->Encrypt(pk, pt3);

    std::cout << "precision bits before encryption: " << pt3->GetLogPrecision() << std::endl;

    //auto derivative_htan_func = [](double x) -> double {  return (1 - tanh(pow(10.0*x,2))); };
    // auto sigmoid = [](double x) -> double {
    // return 20 * (0.25 - pow((1 / (1 + exp(-20 * x)) - 0.5), 2));
    // };

    std::vector<Ciphertext<DCRTPoly>> sender_vals;
    //sender_vals.push_back(test_ctext);
  //  sender_vals.push_back(test_ctext2);

//Ciphertext<DCRTPoly> result_temp_1, result_temp_2, result_temp_3, result_temp_4;


steady_clock::time_point comp_time, comp_end;
comp_time = steady_clock::now();

     size_t j=4;
    size_t k=3;
/*
std::vector<std::thread> threads;
  
// running the code in parallel
for (size_t i=0; i<numQueryVectors; i++)
{
  threads.emplace_back(processQuery, L, R, n, std::ref(results[i]), cc, j, k, low_bound, high_bound, poly_approx_deg);
}

    // threads.emplace_back(processQuery, L, R, n, std::ref(results[0]), cc, j, k, low_bound, high_bound, poly_approx_deg);
    // threads.emplace_back(processQuery, L, R, n, std::ref(results[1]), cc, j, k, low_bound, high_bound, poly_approx_deg);
    // threads.emplace_back(processQuery, L, R, n, std::ref(results[2]), cc, j, k, low_bound, high_bound, poly_approx_deg);
    // threads.emplace_back(processQuery, L, R, n, std::ref(results[3]), cc, j, k, low_bound, high_bound, poly_approx_deg);

    for (auto& thread : threads) {
        thread.join();
    }
  */
//omp_set_num_threads(64);

#pragma omp parallel for
for (size_t i = 0; i < numQueryVectors; ++i) {
    processQuery(L, R, n, results[i], cc, j, k, low_bound, high_bound, poly_approx_deg);
}


    Ciphertext<DCRTPoly> result = cc->EvalAddMany(results);

    comp_end = steady_clock::now();
    long double d11 = duration_cast<measure_typ>(comp_end - comp_time).count();
    std::cout << "COMPUTATION (DEP+Cheby) time with parallelization: " << d11 << "ms" << std::endl;



/*
steady_clock::time_point comp_time, comp_end;

comp_time = steady_clock::now();


// for the first query
    result_temp_2 =  DEP1(L, R, n, result_0, cc);
    //cc->EvalSquareInPlace(result);
    //result =  DEP1(L, 57, 1, result, cc);
    // std::cout << "Number of levels remaining before chebyshev: " << multDepth - result->GetLevel() << std::endl
    //           << std::endl;
    // ------------------------- uncomment from here
    result_temp_2 = cc->EvalChebyshevFunction(derivative_htan_func, result_temp_2, low_bound, high_bound, poly_approx_deg);

    size_t j=4;
    size_t k=3;
     // creating more difference in the zero and non-zero values
    for (size_t m = 0; m < j; m++) {
      cc->EvalSquareInPlace(result_temp_2);
    }
    cc->EvalMultInPlace(result_temp_2, 2.7);
    for (size_t m = 0; m < k; m++) {
       cc->EvalSquareInPlace(result_temp_2);
     }

    std::cout << "Number of levels remaining after chebyshev: " << multDepth - result_temp_2->GetLevel() << std::endl
              << std::endl;

// for the second query

result_temp_1 =  DEP1(L, R, n, result_1, cc);
//cc->EvalSquareInPlace(result);
//result =  DEP1(L, 57, 1, result, cc);
// std::cout << "Number of levels remaining before chebyshev: " << multDepth - result->GetLevel() << std::endl
//           << std::endl;
// ------------------------- uncomment from here
result_temp_1 = cc->EvalChebyshevFunction(derivative_htan_func, result_temp_1, low_bound, high_bound, poly_approx_deg);

 // creating more difference in the zero and non-zero values
for (size_t m = 0; m < j; m++) {
  cc->EvalSquareInPlace(result_temp_1);
}
cc->EvalMultInPlace(result_temp_1, 2.7);
for (size_t m = 0; m < k; m++) {
   cc->EvalSquareInPlace(result_temp_1);
 }

std::cout << "Number of levels remaining after chebyshev: " << multDepth - result_temp_1->GetLevel() << std::endl
          << std::endl;


// for third query

result_temp_3 =  DEP1(L, R, n, result_2, cc);
//cc->EvalSquareInPlace(result);
//result =  DEP1(L, 57, 1, result, cc);
// std::cout << "Number of levels remaining before chebyshev: " << multDepth - result->GetLevel() << std::endl
//           << std::endl;
// ------------------------- uncomment from here
result_temp_3 = cc->EvalChebyshevFunction(derivative_htan_func, result_temp_3, low_bound, high_bound, poly_approx_deg);

 // creating more difference in the zero and non-zero values
for (size_t m = 0; m < j; m++) {
  cc->EvalSquareInPlace(result_temp_3);
}
cc->EvalMultInPlace(result_temp_3, 2.7);
for (size_t m = 0; m < k; m++) {
   cc->EvalSquareInPlace(result_temp_3);
 }

std::cout << "Number of levels remaining after chebyshev: " << multDepth - result_temp_3->GetLevel() << std::endl
          << std::endl;

// for fourth query

result_temp_4 =  DEP1(L, R, n, result_3, cc);
//cc->EvalSquareInPlace(result);
//result =  DEP1(L, 57, 1, result, cc);
// std::cout << "Number of levels remaining before chebyshev: " << multDepth - result->GetLevel() << std::endl
//           << std::endl;
// ------------------------- uncomment from here
result_temp_4 = cc->EvalChebyshevFunction(derivative_htan_func, result_temp_4, low_bound, high_bound, poly_approx_deg);

 // creating more difference in the zero and non-zero values
for (size_t m = 0; m < j; m++) {
  cc->EvalSquareInPlace(result_temp_4);
}
cc->EvalMultInPlace(result_temp_4, 2.7);
for (size_t m = 0; m < k; m++) {
   cc->EvalSquareInPlace(result_temp_4);
 }

std::cout << "Number of levels remaining after chebyshev: " << multDepth - result_temp_4->GetLevel() << std::endl
          << std::endl;


Ciphertext<DCRTPoly> result = cc->EvalAdd(result_temp_1, result_temp_2);
cc->EvalAddInPlace(result, result_temp_3);
cc->EvalAddInPlace(result, result_temp_4);

comp_end = steady_clock::now();

long double d11 = duration_cast<measure_typ>(comp_end - comp_time).count();
    cout << "COMPUTATION time w/o parallelization: " << d11 << "ms" << endl;

*/



    //result = cc->EvalAddManyInPlace(sender_vals);
    // cc->EvalSquareInPlace(result);
    // cc->EvalMultInPlace(result, 1000); // scaling -> can be omitted

    end = steady_clock::now();
    long double d = duration_cast<measure_typ>(end - start).count();
    cout << "Evaluation time for the whole program: " << d << "ms" << endl;

    long double d1 = duration_cast<measure_typ>(end_cc - start_cc).count();
    cout << "Evaluation time for the cc initialization: " << d1 << "ms" << endl;

    Plaintext pt1;
    cc->Decrypt(keyPair.secretKey, result, &pt1);
    std::cout << "precision bits after decryption: " << pt1->GetLogPrecision() << std::endl;

    std::vector<double> vec_result2 = pt1->GetRealPackedValue();

    printFirst20Values(vec_result2);

    double result0 = 0.0;
    std::cout << "\n";
    for (size_t i = 0; i < test_vals.size(); i++) {
    // std::cout << "Output after Chebyshev, test_vals[" << i
    //           << "]:" << test_vals[i] << ", result after = vec_result[" << i << "]:" << vec_result2[i] << std::endl;

              // Accumulate the results by alternating the signs
        //if (i % 2 == 0) {
            result0 += vec_result2[i];
        //} else {
        //    result0 -= vec_result2[i];
        //}

        //result0 += vec_result2[i];
    }

     std::cout << "Final result after accumulating: " << result0 << std::endl;

     std::vector<std::pair<double, double>> sorted_pairs;

    for (int i = 0; i < vec_result2.size(); ++i) {
        sorted_pairs.push_back(std::make_pair(vec_result2[i], test_vals[i]));
    }

    // Sort the vector of pairs in descending order based on the values
    std::sort(sorted_pairs.begin(), sorted_pairs.end(), std::greater<std::pair<double, double>>());

    // Print out the 30 largest values along with their indices
    std::cout << "The 30 largest values and their indices:" << std::endl;
    for (int i = 0; i < 30 && i < sorted_pairs.size(); ++i) {
        std::cout << "Test_vals " << sorted_pairs[i].second << ": " << sorted_pairs[i].first << std::endl;
    }



  }
