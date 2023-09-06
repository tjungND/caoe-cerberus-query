// g++ -std=c++17 -o dep_cheby dep_cheby.cpp -DOPENFHE_VERSION=1.0.3 -Wno-parentheses -DMATHBACKEND=4 -Wl,-rpath,/usr/local/lib/ /usr/local/lib/libOPENFHEcore.so /usr/local/lib/libOPENFHEpke.so /usr/local/lib/libOPENFHEpke_static.a /usr/local/lib/libOPENFHEcore_static.a -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/ -lstdc++fs -O3 -fopenmp


#include "openfhe.h"
#include <cmath>
#include <ctime>
#include <cassert>

#include <iostream>
#include <vector>
#include <algorithm>
#include <random>


using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

void EvalFunctionExample();

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


int main(int argc, char* argv[]) {
    EvalFunctionExample();
    return 0;
}


void EvalFunctionExample() {
    std::cout << "--------------------------------- EVAL DEP CHEBYSHEV FUNCTION ---------------------------------"
              << std::endl;
    CCParams<CryptoContextCKKSRNS> parameters;


    //parameters.SetRingDim(1 << 15);

    double L = 2.5;
    int n = 9;
    double R = 150;

    uint32_t multDepth = 48;
    unsigned int poly_approx_deg = 75;
    uint32_t batchSize = 32768;

    long low_bound = -R;
    long high_bound = R;

    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(80);
    parameters.SetBatchSize(batchSize);


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

    uint32_t batchSize1 = parameters.GetBatchSize();
    std::cout << "batchSize: " << batchSize1 << std::endl;

    std::cout << "Range is +-" << R * std::pow(L, n) << std::endl;

    std::cout << "scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    std::cout << "ring dimension: " << cc->GetRingDimension() << std::endl;
    std::cout << "noise estimate: " << parameters.GetNoiseEstimate() << std::endl;
    std::cout << "multiplicative depth: " << multDepth << std::endl;
    std::cout << "polynomial approx degree for chebyshev: " << poly_approx_deg << std::endl;


    // std::vector<double> test_vals = {
    //     (511758),
    //     (19588.5),
    //     (500),
    //     (10.5),
    //     (9),
    //     (5),
    //     (4),
    //     (0.0),
    //     (4),
    //     (5),
    //     (9),
    //     (10),
    //     (-20.5),
    //     (-511758)
    // };

    std::vector<double> test_vals;

    // Generate values from -99000 to -3
    for (double i = -572204; i <= -3; ++i) {
        test_vals.push_back(i);
    }

    // Generate values from 3 to 99000
    for (double i = 4; i <= 572204; ++i) {
        test_vals.push_back(i);
    }
    // Shuffle the elements randomly
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(test_vals.begin(), test_vals.end(), g);

    // Resize the test_vals to 32768, keeping the first 32768 elements
    if (test_vals.size() > 32768) {
        test_vals.resize(32767);
    }

    test_vals.push_back(0.0);

    Ciphertext<DCRTPoly> test_ctext;
    Plaintext pt3 = cc->MakeCKKSPackedPlaintext(test_vals);
    test_ctext = cc->Encrypt(pk, pt3);

    std::cout << "precision bits before encryption: " << pt3->GetLogPrecision() << std::endl;

    auto derivative_htan_func = [](double x) -> double {  return 1 - tanh(pow(x,2)); };

    Ciphertext<DCRTPoly> result;
    steady_clock::time_point start, end;
    start = steady_clock::now();

    result =  DEP1(L, R, n, test_ctext, cc);
    cc->EvalSquareInPlace(result);

    result = cc->EvalChebyshevFunction(derivative_htan_func, result, 0, 22500, poly_approx_deg);

    cc->EvalSquareInPlace(result); // creating more difference in the zero and non-zero values

    cc->EvalMultInPlace(result, 10000000000); // scaling -> can be omitted

    end = steady_clock::now();
    long double d = duration_cast<measure_typ>(end - start).count();
    cout << "Evaluation time: " << d << "ms" << endl;

    Plaintext pt1;
    cc->Decrypt(keyPair.secretKey, result, &pt1);
    std::cout << "precision bits after decryption: " << pt1->GetLogPrecision() << std::endl;

    std::vector<double> vec_result2 = pt1->GetRealPackedValue();

    double result0 = 0.0;
    std::cout << "\n";
    for (size_t i = 0; i < test_vals.size()+1; i++) {
    // std::cout << "Output after Chebyshev, test_vals[" << i
    //           << "]:" << test_vals[i] << ", result after = vec_result[" << i << "]:" << vec_result2[i] << std::endl;

              // Accumulate the results by alternating the signs
        if (i % 2 == 0) {
            result0 += vec_result2[i];
        } else {
            result0 -= vec_result2[i];
        }
    }

     std::cout << "Final result after accumulating with alternating signs: " << result0 << std::endl;

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
