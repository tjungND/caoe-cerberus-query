//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example of evaluating arbitrary smooth functions with the Chebyshev approximation using CKKS.
 */

#include "openfhe.h"
#include <cmath>
#include <ctime>


using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

void EvalFunctionExample();

// CalculateApproximationError() calculates the precision number (or approximation error).
// The higher the precision, the less the error.
double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                   const std::vector<std::complex<double>>& expectedResult) {
    if (result.size() != expectedResult.size())
        OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

    // using the infinity norm
    double maxError = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        double error = std::abs(result[i].real() - expectedResult[i].real());
        if (maxError < error)
            maxError = error;
    }

    return std::abs(std::log2(maxError));
}

int main(int argc, char* argv[]) {
    EvalFunctionExample();
    return 0;
}


void EvalFunctionExample() {
    std::cout << "--------------------------------- EVAL CHEBYSHEV FUNCTION ---------------------------------"
              << std::endl;
    CCParams<CryptoContextCKKSRNS> parameters;

    // We set a smaller ring dimension to improve performance for this example.
    // In production environments, the security level should be set to
    // HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    // or 256-bit security, respectively.
    //parameters.SetSecurityLevel(HEStd_128_classic);
    //parameters.SetRingDim(1 << 15);
    uint32_t multDepth = 4;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(59);
    parameters.SetDesiredPrecision(50);


    // Choosing a higher degree yields better precision, but a longer runtime.
    //uint32_t polyDegree = 50;

    // The multiplicative depth depends on the polynomial degree.
    // See the FUNCTION_EVALUATION.md file for a table mapping polynomial degrees to multiplicative depths.

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    // We need to enable Advanced SHE to use the Chebyshev approximation.
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    // We need to generate mult keys to run Chebyshev approximations.
    cc->EvalMultKeyGen(keyPair.secretKey);
    auto pk = keyPair.publicKey;

    std::cout << "scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    //std::cout << "Mod size bits: " << parameters.GetFirstModSize() << std::endl;
    std::cout << "ring dimension: " << cc->GetRingDimension() << std::endl;
    std::cout << "noise estimate: " << parameters.GetNoiseEstimate() << std::endl;
    
    //int p = cc->MakePlaintext().ConvertToInt();
    //std::cout << "plaintext space: " << p << std::endl;
    int power = 30;

    std::vector<double> test_vals;

    test_vals.push_back(0);
    for (int i = 1; i <= power; i++) {
        double value = 1 << i;  // Bit shifting to calculate powers of 2
        test_vals.push_back(sqrt(value));
        cout << test_vals[i] <<endl;
    }
    cout << "-------" << endl;

         test_vals.push_back(sqrt(400000000));
        cout << sqrt(400000000) << endl;

      test_vals.push_back(sqrt(700000000));
        cout << sqrt(700000000) << endl;
    
        test_vals.push_back(sqrt(800000000));
        cout << sqrt(800000000) << endl;
   
    test_vals.push_back(sqrt(900000000));
        cout << sqrt(900000000) << endl;

    test_vals.push_back(sqrt(1000000000));
    cout << sqrt(1000000000) << endl;

    test_vals.push_back(sqrt(1005600000));
        cout << sqrt(1005600000) << endl;

    test_vals.push_back(sqrt(1009800000));
        cout << sqrt(1009800000) << endl;

    test_vals.push_back(sqrt(1070000000));
        cout << sqrt(1070000000) << endl;


    test_vals.push_back(sqrt(4));
        cout << sqrt(4) << endl;
   
    
    size_t encodedLength = test_vals.size();
    cout << "test_vals length: " << encodedLength << endl;

    // result of evaluating f(x) = 2048/ (1+ (8*x)^4), K = 2048, S= 8
    Ciphertext<DCRTPoly> test_vals_ctexts;
    unsigned int batchsize = cc->GetEncodingParams()->GetBatchSize();
    std::cout.precision(10);



    //vector<double> packed_vals(batchsize, (double)test_vals);
    Plaintext pt = cc->MakeCKKSPackedPlaintext(test_vals);
    test_vals_ctexts = cc->Encrypt(pk, pt);

    Plaintext pt1;
    constexpr unsigned int K = 1 << 12;
    constexpr unsigned int S = 1 << 6;
    unsigned int poly_approx_deg = 5;
    long low_bound = 0;
    long high_bound = 1073741824;

    std::cout << " K: " << K << std::endl;
    std::cout << " S: " << S << std::endl;
    std::cout << " poly_approx_deg: " << poly_approx_deg << std::endl;
    std::cout << " low_bound: " << low_bound << std::endl;
    std::cout << " high_bound: " << high_bound << std::endl;
    std::cout << "\n" << std::endl;


    //cc->EvalMultInPlace(test_vals_ctexts, S);
    //cc->EvalSquareInPlace(test_vals_ctexts);
    //cc->EvalMultInPlace(test_vals_ctexts, 0.001);
    //cc->EvalSquareInPlace(test_vals_ctexts);
    //cc->EvalAddInPlace(test_vals_ctexts, 1);

    //std::cout << "noise estimate: " << test_vals_ctexts->GetNoiseScaleDeg() << std::endl;
    //std::cout << "level: " << test_vals_ctexts->GetLevel() << std::endl;

    // cc->Decrypt(keyPair.secretKey, test_vals_ctexts, &pt1);
    // const std::vector<double> &vec_result = pt1->GetRealPackedValue();

    // std::cout << "\n";
    // for (size_t i = 0; i < encodedLength; i++) {
    // std::cout << "Output before Chebyshev, test_vals[" << i
    //           << "]:" << vec_result[i] << std::endl;
    // }

    // if (x>0.68){return 0.0;} else {return K;};


     //1) Method 1: Using tanh derivative
     //test_vals_ctexts = cc->EvalChebyshevFunction([](double x) -> double { return 1- pow(std::tanh(x),2); }, // employ frobenius here for squaring
      //    test_vals_ctexts, low_bound, high_bound, poly_approx_deg);

    //2) Method 2: Using original polynomial
    // test_vals_ctexts = cc->EvalChebyshevFunction(
    //     [&S, &K](double x) -> double {
    //       double y = x * S;
    //       double y_sq = y * y;
    //       double y_qu = y_sq * y_sq;
    //       return K / (1 + (y_qu));
    //     },
    //     test_vals_ctexts, low_bound, high_bound, poly_approx_deg);

    // 3) Using plain division
    //cc->EvalSquareInPlace(test_vals_ctexts);
    steady_clock::time_point start, end;

    start = steady_clock::now();
    //test_vals_ctexts = cc->EvalDivide(test_vals_ctexts, low_bound, high_bound, poly_approx_deg);
    cc->EvalSquareInPlace(test_vals_ctexts);
    test_vals_ctexts = cc->EvalChebyshevFunction([](double x) -> double { return 1/x; }, // employ frobenius here for squaring
           test_vals_ctexts, low_bound, high_bound, poly_approx_deg);
    end = steady_clock::now();
    long double d = duration_cast<measure_typ>(end - start).count();
    cout << "Evaluation time: " << d << "ms" << endl;

// test_vals_ctexts = cc->EvalChebyshevFunction([](double x) -> double { return exp(-x); }, // employ frobenius here for squaring
//           test_vals_ctexts, low_bound, high_bound, poly_approx_deg);



    cc->Decrypt(keyPair.secretKey, test_vals_ctexts, &pt1);
    const std::vector<double> &vec_result2 = pt1->GetRealPackedValue();

    //  uint32_t precision =
    //     std::floor(CalculateApproximationError(pt1->GetCKKSPackedValue(), pt->GetCKKSPackedValue()));
    // std::cout << "Bootstrapping precision after 1 iteration: " << precision << std::endl;

    std::cout << "\n";
    for (size_t i = 0; i < encodedLength; i++) {
    std::cout << "Output after Chebyshev, test_vals[" << i
              << "]:" << vec_result2[i] << std::endl;
    }



    //cc->EvalSquareInPlace(test_vals_ctexts);  // employ frobenius here for squaring
    //cc->EvalNegateInPlace(test_vals_ctexts);
    //cc->EvalAddInPlace(test_vals_ctexts, 1);

     //cc->EvalSquareInPlace(test_vals_ctexts);
     //cc->EvalMultInPlace(test_vals_ctexts, K);

    // cc->EvalMultInPlace(tconstest_vals_ctexts, 5);
    // //cc->EvalSquareInPlace(test_vals_ctexts);

    //  cc->Decrypt(keyPair.secretKey, test_vals_ctexts, &pt1);
    //  const std::vector<double> &vec_result1 = pt1->GetRealPackedValue();

    //  std::cout << "\n";
    //  for (size_t i = 0; i < encodedLength; i++) {
    //  std::cout << "Output after mult., test_vals[" << i
    //            << "]:" << vec_result1[i] << std::endl;
    //  }


  }
/*
    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, test_vals_ctexts[0], &plaintextDec);
    plaintextDec->SetLength(encodedLength);

    for (size_t i = 0; i < test_vals.size(); i++) {

    }

    std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout << "Output for test_vals[0] \n\t" << finalResult << std::endl << std::endl;

    // test_vals 1
    cc->Decrypt(keyPair.secretKey, test_vals_ctexts[1], &plaintextDec);
    plaintextDec->SetLength(encodedLength);

    finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout << "Output for test_vals[1] \n\t" << finalResult << std::endl << std::endl;

    // test_vals 2
    cc->Decrypt(keyPair.secretKey, test_vals_ctexts[2], &plaintextDec);
    plaintextDec->SetLength(encodedLength);

    finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout << "Output for test_vals[2] \n\t" << finalResult << std::endl << std::endl;

    // test_vals 3
    cc->Decrypt(keyPair.secretKey, test_vals_ctexts[3], &plaintextDec);
    plaintextDec->SetLength(encodedLength);

    finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout << "Output for test_vals[3] \n\t" << finalResult << std::endl << std::endl;

    // test_vals 4
    cc->Decrypt(keyPair.secretKey, test_vals_ctexts[4], &plaintextDec);
    plaintextDec->SetLength(encodedLength);

    finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout << "Output for test_vals[4] \n\t" << finalResult << std::endl << std::endl;

    std::cout << "Expected\n\t" << expected_vals << std::endl << std::endl;

    std::cout << "--------------------------------- END EVAL CHEBYSHEV FUNCTION ---------------------------------"
              << std::endl;
}
*/
