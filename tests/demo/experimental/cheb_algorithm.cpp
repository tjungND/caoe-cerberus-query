#include <iostream>
#include <vector>
#include <cmath>
#include <functional>
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

double PREC = std::pow(2, -20);

inline bool IsNotEqualOne(double val) {
    if (1 - PREC >= val) {
        return true;
    }
    if (1 + PREC <= val) {
        return true;
    }
    return false;
}


// Ciphertext<DCRTPoly> InnerEvalChebyshevPS(ConstCiphertext<DCRTPoly> x,
//                                                               const std::vector<double>& coefficients, uint32_t k,
//                                                               uint32_t m, std::vector<Ciphertext<DCRTPoly>>& T,
//                                                               std::vector<Ciphertext<DCRTPoly>>& T2) const {
//     auto cc = x->GetCryptoContext();

//     // Compute k*2^{m-1}-k because we use it a lot
//     uint32_t k2m2k = k * (1 << (m - 1)) - k;

//     // Divide coefficients by T^{k*2^{m-1}}
//     std::vector<double> Tkm(int32_t(k2m2k + k) + 1, 0.0);
//     Tkm.back() = 1;
//     auto divqr = LongDivisionChebyshev(coefficients, Tkm);

//     // Subtract x^{k(2^{m-1} - 1)} from r
//     std::vector<double> r2 = divqr->r;
//     if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
//         r2[int32_t(k2m2k)] -= 1;
//         r2.resize(Degree(r2) + 1);
//     }
//     else {
//         r2.resize(int32_t(k2m2k + 1), 0.0);
//         r2.back() = -1;
//     }

//     // Divide r2 by q
//     auto divcs = LongDivisionChebyshev(r2, divqr->q);

//     // Add x^{k(2^{m-1} - 1)} to s
//     std::vector<double> s2 = divcs->r;
//     s2.resize(int32_t(k2m2k + 1), 0.0);
//     s2.back() = 1;

//     // Evaluate c at u
//     Ciphertext<DCRTPoly> cu;
//     uint32_t dc = Degree(divcs->q);
//     bool flag_c = false;
//     if (dc >= 1) {
//         if (dc == 1) {
//             if (divcs->q[1] != 1) {
//                 cu = cc->EvalMult(T.front(), divcs->q[1]);
//                 cc->ModReduceInPlace(cu);
//             }
//             else {
//                 cu = T.front();
//             }
//         }
//         else {
//             std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
//             std::vector<double> weights(dc);

//             for (uint32_t i = 0; i < dc; i++) {
//                 ctxs[i]    = T[i];
//                 weights[i] = divcs->q[i + 1];
//             }

//             cu = cc->EvalLinearWSumMutable(ctxs, weights);
//         }

//         // adds the free term (at x^0)
//         cc->EvalAddInPlace(cu, divcs->q.front() / 2);
//         // Need to reduce levels up to the level of T2[m-1].
//         usint levelDiff = T2[m - 1]->GetLevel() - cu->GetLevel();
//         cc->LevelReduceInPlace(cu, nullptr, levelDiff);

//         flag_c = true;
//     }

//     // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
//     Ciphertext<DCRTPoly> qu;

//     if (Degree(divqr->q) > k) {
//         qu = InnerEvalChebyshevPS(x, divqr->q, k, m - 1, T, T2);
//     }
//     else {
//         // dq = k from construction
//         // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
//         auto qcopy = divqr->q;
//         qcopy.resize(k);
//         if (Degree(qcopy) > 0) {
//             std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
//             std::vector<double> weights(Degree(qcopy));

//             for (uint32_t i = 0; i < Degree(qcopy); i++) {
//                 ctxs[i]    = T[i];
//                 weights[i] = divqr->q[i + 1];
//             }

//             qu = cc->EvalLinearWSumMutable(ctxs, weights);
//             // the highest order coefficient will always be a power of two up to 2^{m-1} because q is "monic" but the Chebyshev rule adds a factor of 2
//             // we don't need to increase the depth by multiplying the highest order coefficient, but instead checking and summing, since we work with m <= 4.
//             Ciphertext<DCRTPoly> sum = T[k - 1];
//             for (uint32_t i = 0; i < log2(divqr->q.back()); i++) {
//                 sum = cc->EvalAdd(sum, sum);
//             }
//             cc->EvalAddInPlace(qu, sum);
//         }
//         else {
//             Ciphertext<DCRTPoly> sum = T[k - 1];
//             for (uint32_t i = 0; i < log2(divqr->q.back()); i++) {
//                 sum = cc->EvalAdd(sum, sum);
//             }
//             qu = sum;
//         }

//         // adds the free term (at x^0)
//         cc->EvalAddInPlace(qu, divqr->q.front() / 2);
//         // The number of levels of qu is the same as the number of levels of T[k-1] or T[k-1] + 1.
//         // No need to reduce it to T2[m-1] because it only reaches here when m = 2.
//     }

//     Ciphertext<DCRTPoly> su;

//     if (Degree(s2) > k) {
//         su = InnerEvalChebyshevPS(x, s2, k, m - 1, T, T2);
//     }
//     else {
//         // ds = k from construction
//         // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
//         auto scopy = s2;
//         scopy.resize(k);
//         if (Degree(scopy) > 0) {
//             std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
//             std::vector<double> weights(Degree(scopy));

//             for (uint32_t i = 0; i < Degree(scopy); i++) {
//                 ctxs[i]    = T[i];
//                 weights[i] = s2[i + 1];
//             }

//             su = cc->EvalLinearWSumMutable(ctxs, weights);
//             // the highest order coefficient will always be 1 because s2 is monic.
//             cc->EvalAddInPlace(su, T[k - 1]);
//         }
//         else {
//             su = T[k - 1];
//         }

//         // adds the free term (at x^0)
//         cc->EvalAddInPlace(su, s2.front() / 2);
//         // The number of levels of su is the same as the number of levels of T[k-1] or T[k-1] + 1. Need to reduce it to T2[m-1] + 1.
//         // su = cc->LevelReduce(su, nullptr, su->GetElements()[0].GetNumOfElements() - Lm + 1) ;
//         cc->LevelReduceInPlace(su, nullptr);
//     }

//     Ciphertext<DCRTPoly> result;

//     if (flag_c) {
//         result = cc->EvalAdd(T2[m - 1], cu);
//     }
//     else {
//         result = cc->EvalAdd(T2[m - 1], divcs->q.front() / 2);
//     }

//     result = cc->EvalMult(result, qu);
//     cc->ModReduceInPlace(result);

//     cc->EvalAddInPlace(result, su);

//     return result;
// }



std::vector<double> EvalChebyshevCoefficients(std::function<double(double)> func, double a, double b, uint32_t degree) {
    double bMinusA = 0.5 * (b - a);
    double bPlusA  = 0.5 * (b + a);
    std::vector<double> functionPoints(degree);
    for (size_t i = 0; i < degree; i++) {
        std::cout << "bMinusA: " << bMinusA << std::endl;
        std::cout << "bPlusA: " << bPlusA << std::endl;
        double y = std::cos(M_PI * (i + 0.5) / degree) * bMinusA + bPlusA;
        std::cout << "cos (M_PI * (" << i << "+ 0.5) / degree) * bMinusA + bPlusA: " << y << std::endl;
        functionPoints[i] = func(y);
        std::cout << "1/ cox(M_PI * (" << i << " + 0.5) / degree) * bMinusA + bPlusA : " << functionPoints[i] << std::endl;
        std::cout << " --------------------- ---------------- ------------------" << std::endl;
    }
    double multFactor = 2.0 / degree;

    std::vector<double> coefficients(degree, 0);
    for (size_t i = 0; i < degree; i++) {
        for (size_t j = 0; j < degree; j++) {
            double y = functionPoints[j];
            std::cout << "functionPoints[j]: " << y << std::endl;
            double x = std::cos(M_PI * i * (j + 0.5) / degree);
            std::cout << "cos(M_PI * i * (j + 0.5) / degree): " << x << std::endl;
            coefficients[i] += (y*x);
            std::cout << "coefficients[i]: " << coefficients[i] << std::endl;
             std::cout << " --------------------- ---------------- ------------------" << std::endl;
        }
        coefficients[i] *= multFactor;
    }

    return coefficients;
}

/*Return the degree of the polynomial described by coefficients,
which is the index of the last non-zero element in the coefficients - 1.
Don't throw an error if all the coefficients are zero, but return 0. */
uint32_t Degree1(const std::vector<double>& coefficients) {
    uint32_t deg = 1;
    for (int i = coefficients.size() - 1; i > 0; i--) {
        if (coefficients[i] == 0) {
            deg += 1;
        }
        else
            break;
    }
    return coefficients.size() - deg;
}

Ciphertext<DCRTPoly> EvalChebyshevSeriesLinear1(Ciphertext<DCRTPoly> x,
                                                                std::vector<double>& coefficients, double a,
                                                                   double b, KeyPair<DCRTPoly> keys) {
    usint k = coefficients.size() - 1;

    // computes linear transformation y = -1 + 2 (x-a)/(b-a)
    // consumes one level when a <> -1 && b <> 1
    auto cc = x->GetCryptoContext();
    std::vector<Ciphertext<DCRTPoly>> T(k); // creating k sized vector
    if ((a - std::round(a) < 1e-10) && (b - std::round(b) < 1e-10) && (std::round(a) == -1) && (std::round(b) == 1)) {
        T[0] = x->Clone();
    }
    else {
        // linear transformation is needed
        double alpha = 2 / (b - a);
        double beta  = 2 * a / (b - a);

        T[0] = cc->EvalMult(x, alpha);
        cc->ModReduceInPlace(T[0]);
        cc->EvalAddInPlace(T[0], -1.0 - beta);
    }

    Ciphertext<DCRTPoly> yReduced = T[0]->Clone();

    // Computes Chebyshev polynomials up to degree k
    // for y: T_1(y) = y, T_2(y), ... , T_k(y)
    // uses binary tree multiplication
    for (size_t i = 2; i <= k; i++) {
        // if i is a power of two
        if (!(i & (i - 1))) {
            // compute T_{2i}(y) = 2*T_i(y)^2 - 1
            auto square = cc->EvalSquare(T[i / 2 - 1]);
            T[i - 1]    = cc->EvalAdd(square, square);
            cc->ModReduceInPlace(T[i - 1]);
            cc->EvalAddInPlace(T[i - 1], -1.0);
            // TODO: (Andrey) Do we need this?
            if (i == 2) {
                cc->LevelReduceInPlace(T[i / 2 - 1], nullptr);
                cc->LevelReduceInPlace(yReduced, nullptr);
            }
            cc->LevelReduceInPlace(yReduced, nullptr);  // depth log_2 i + 1

            // i/2 will now be used only at a lower level
            if (i / 2 > 1) {
                cc->LevelReduceInPlace(T[i / 2 - 1], nullptr);
            }
            // TODO: (Andrey) until here.
            // If we need it, we can also add it in EvalChebyshevSeriesPS
        }
        else {
            // non-power of 2
            if (i % 2 == 1) {
                // if i is odd
                // compute T_{2i+1}(y) = 2*T_i(y)*T_{i+1}(y) - y
                auto prod = cc->EvalMult(T[i / 2 - 1], T[i / 2]);
                T[i - 1]  = cc->EvalAdd(prod, prod);
                cc->ModReduceInPlace(T[i - 1]);
                cc->EvalSubInPlace(T[i - 1], yReduced);
            }
            else {
                // i is even but not power of 2
                // compute T_{2i}(y) = 2*T_i(y)^2 - 1
                auto square = cc->EvalSquare(T[i / 2 - 1]);
                T[i - 1]    = cc->EvalAdd(square, square);
                cc->ModReduceInPlace(T[i - 1]);
                cc->EvalAddInPlace(T[i - 1], -1.0);
            }
        }
    }
    for (size_t i = 1; i < k; i++) {
        usint levelDiff = T[k - 1]->GetLevel() - T[i - 1]->GetLevel();
        cc->LevelReduceInPlace(T[i - 1], nullptr, levelDiff);
    }
// ------------------------

     Plaintext pt;
    cc->Decrypt(keys.secretKey, T[0], &pt);
    const std::vector<double> &vec_result = pt->GetRealPackedValue();

    std::cout << "\n";
    for (size_t i = 0; i < 8; i++) {
    std::cout << "Intermediate polynomial-- result[" << i
              << "]:" << vec_result[i] << std::endl;
    }



// ------------------------
    // perform scalar multiplication for the highest-order term
    auto result = cc->EvalMult(T[k - 1], coefficients[k]);

    // perform scalar multiplication for all other terms and sum them up
    for (size_t i = 0; i < k - 1; i++) {
        if (coefficients[i + 1] != 0) {
            cc->EvalMultInPlace(T[i], coefficients[i + 1]);
            cc->EvalAddInPlace(result, T[i]);
        }
    }

    // Do rescaling after scalar multiplication
    cc->ModReduceInPlace(result);

    // adds the free term (at x^0)
    cc->EvalAddInPlace(result, coefficients[0] / 2);

    return result;
}

// Ciphertext<DCRTPoly> EvalChebyshevSeriesPS1(ConstCiphertext<DCRTPoly> x,
//                                                                const std::vector<double>& coefficients, double a,
//                                                                double b) const {
//     uint32_t n = Degree(coefficients);

//     std::vector<double> f2 = coefficients;

//     // Make sure the coefficients do not have the zero dominant terms
//     if (coefficients[coefficients.size() - 1] == 0)
//         f2.resize(n + 1);

//     std::vector<uint32_t> degs = ComputeDegreesPS(n);
//     uint32_t k                 = degs[0];
//     uint32_t m                 = degs[1];

//     //  std::cerr << "\n Degree: n = " << n << ", k = " << k << ", m = " << m << endl;

//     // computes linear transformation y = -1 + 2 (x-a)/(b-a)
//     // consumes one level when a <> -1 && b <> 1
//     auto cc = x->GetCryptoContext();
//     std::vector<Ciphertext<DCRTPoly>> T(k);
//     if ((a - std::round(a) < 1e-10) && (b - std::round(b) < 1e-10) && (std::round(a) == -1) && (std::round(b) == 1)) {
//         // no linear transformation is needed if a = -1, b = 1
//         // T_1(y) = y
//         T[0] = x->Clone();
//     }
//     else {
//         // linear transformation is needed
//         double alpha = 2 / (b - a);
//         double beta  = 2 * a / (b - a);

//         T[0] = cc->EvalMult(x, alpha);
//         cc->ModReduceInPlace(T[0]);
//         cc->EvalAddInPlace(T[0], -1.0 - beta);
//     }

//     Ciphertext<DCRTPoly> y = T[0]->Clone();

//     // Computes Chebyshev polynomials up to degree k
//     // for y: T_1(y) = y, T_2(y), ... , T_k(y)
//     // uses binary tree multiplication
//     for (uint32_t i = 2; i <= k; i++) {
//         // if i is a power of two
//         if (!(i & (i - 1))) {
//             // compute T_{2i}(y) = 2*T_i(y)^2 - 1
//             auto square = cc->EvalSquare(T[i / 2 - 1]);
//             T[i - 1]    = cc->EvalAdd(square, square);
//             cc->ModReduceInPlace(T[i - 1]);
//             cc->EvalAddInPlace(T[i - 1], -1.0);
//         }
//         else {
//             // non-power of 2
//             if (i % 2 == 1) {
//                 // if i is odd
//                 // compute T_{2i+1}(y) = 2*T_i(y)*T_{i+1}(y) - y
//                 auto prod = cc->EvalMult(T[i / 2 - 1], T[i / 2]);
//                 T[i - 1]  = cc->EvalAdd(prod, prod);

//                 cc->ModReduceInPlace(T[i - 1]);
//                 cc->EvalSubInPlace(T[i - 1], y);
//             }
//             else {
//                 // i is even but not power of 2
//                 // compute T_{2i}(y) = 2*T_i(y)^2 - 1
//                 auto square = cc->EvalSquare(T[i / 2 - 1]);
//                 T[i - 1]    = cc->EvalAdd(square, square);
//                 cc->ModReduceInPlace(T[i - 1]);
//                 cc->EvalAddInPlace(T[i - 1], -1.0);
//             }
//         }
//     }

//     const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(T[k - 1]->GetCryptoParameters());

//     auto algo = cc->GetScheme();

//     if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
//         // brings all powers of x to the same level
//         for (size_t i = 1; i < k; i++) {
//             usint levelDiff = T[k - 1]->GetLevel() - T[i - 1]->GetLevel();
//             cc->LevelReduceInPlace(T[i - 1], nullptr, levelDiff);
//         }
//     }
//     else {
//         for (size_t i = 1; i < k; i++) {
//             algo->AdjustLevelsAndDepthInPlace(T[i - 1], T[k - 1]);
//         }
//     }

//     std::vector<Ciphertext<DCRTPoly>> T2(m);
//     // Compute the Chebyshev polynomials T_{2k}(y), T_{4k}(y), ... , T_{2^{m-1}k}(y)
//     T2.front() = T.back();
//     for (uint32_t i = 1; i < m; i++) {
//         auto square = cc->EvalSquare(T2[i - 1]);
//         T2[i]       = cc->EvalAdd(square, square);
//         cc->ModReduceInPlace(T2[i]);
//         cc->EvalAddInPlace(T2[i], -1.0);
//     }

//     // computes T_{k(2*m - 1)}(y)
//     auto T2km1 = T2.front();
//     for (uint32_t i = 1; i < m; i++) {
//         // compute T_{k(2*m - 1)} = 2*T_{k(2^{m-1}-1)}(y)*T_{k*2^{m-1}}(y) - T_k(y)
//         auto prod = cc->EvalMult(T2km1, T2[i]);
//         T2km1     = cc->EvalAdd(prod, prod);
//         cc->ModReduceInPlace(T2km1);
//         cc->EvalSubInPlace(T2km1, T2.front());
//     }

//     // We also need to reduce the number of levels of T[k-1] and of T2[0] by another level.
//     //  cc->LevelReduceInPlace(T[k-1], nullptr);
//     //  cc->LevelReduceInPlace(T2.front(), nullptr);

//     // Compute k*2^{m-1}-k because we use it a lot
//     uint32_t k2m2k = k * (1 << (m - 1)) - k;

//     // Add T^{k(2^m - 1)}(y) to the polynomial that has to be evaluated
//     f2.resize(2 * k2m2k + k + 1, 0.0);
//     f2.back() = 1;

//     // Divide f2 by T^{k*2^{m-1}}
//     std::vector<double> Tkm(int32_t(k2m2k + k) + 1, 0.0);
//     Tkm.back() = 1;
//     auto divqr = LongDivisionChebyshev(f2, Tkm);

//     // Subtract x^{k(2^{m-1} - 1)} from r
//     std::vector<double> r2 = divqr->r;
//     if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
//         r2[int32_t(k2m2k)] -= 1;
//         r2.resize(Degree(r2) + 1);
//     }
//     else {
//         r2.resize(int32_t(k2m2k + 1), 0.0);
//         r2.back() = -1;
//     }

//     // Divide r2 by q
//     auto divcs = LongDivisionChebyshev(r2, divqr->q);

//     // Add x^{k(2^{m-1} - 1)} to s
//     std::vector<double> s2 = divcs->r;
//     s2.resize(int32_t(k2m2k + 1), 0.0);
//     s2.back() = 1;

//     // Evaluate c at u
//     Ciphertext<DCRTPoly> cu;
//     uint32_t dc = Degree(divcs->q);
//     bool flag_c = false;
//     if (dc >= 1) {
//         if (dc == 1) {
//             if (divcs->q[1] != 1) {
//                 cu = cc->EvalMult(T.front(), divcs->q[1]);
//                 cc->ModReduceInPlace(cu);
//             }
//             else {
//                 cu = T.front();
//             }
//         }
//         else {
//             std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
//             std::vector<double> weights(dc);

//             for (uint32_t i = 0; i < dc; i++) {
//                 ctxs[i]    = T[i];
//                 weights[i] = divcs->q[i + 1];
//             }

//             cu = cc->EvalLinearWSumMutable(ctxs, weights);
//         }

//         // adds the free term (at x^0)
//         cc->EvalAddInPlace(cu, divcs->q.front() / 2);
//         // TODO : Andrey why not T2[m-1]->GetLevel() instead?
//         // Need to reduce levels to the level of T2[m-1].
//         //    usint levelDiff = y->GetLevel() - cu->GetLevel() + ceil(log2(k)) + m - 1;
//         //    cc->LevelReduceInPlace(cu, nullptr, levelDiff);

//         flag_c = true;
//     }

//     // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
//     Ciphertext<DCRTPoly> qu;

//     if (Degree(divqr->q) > k) {
//         qu = InnerEvalChebyshevPS(x, divqr->q, k, m - 1, T, T2);
//     }
//     else {
//         // dq = k from construction
//         // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
//         auto qcopy = divqr->q;
//         qcopy.resize(k);
//         if (Degree(qcopy) > 0) {
//             std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
//             std::vector<double> weights(Degree(qcopy));

//             for (uint32_t i = 0; i < Degree(qcopy); i++) {
//                 ctxs[i]    = T[i];
//                 weights[i] = divqr->q[i + 1];
//             }

//             qu = cc->EvalLinearWSumMutable(ctxs, weights);
//             // the highest order coefficient will always be 2 after one division because of the Chebyshev division rule
//             Ciphertext<DCRTPoly> sum = cc->EvalAdd(T[k - 1], T[k - 1]);
//             cc->EvalAddInPlace(qu, sum);
//         }
//         else {
//             qu = T[k - 1];

//             for (uint32_t i = 1; i < divqr->q.back(); i++) {
//                 cc->EvalAddInPlace(qu, T[k - 1]);
//             }
//         }

//         // adds the free term (at x^0)
//         cc->EvalAddInPlace(qu, divqr->q.front() / 2);
//         // The number of levels of qu is the same as the number of levels of T[k-1] + 1.
//         // Will only get here when m = 2, so the number of levels of qu and T2[m-1] will be the same.
//     }

//     Ciphertext<DCRTPoly> su;

//     if (Degree(s2) > k) {
//         su = InnerEvalChebyshevPS(x, s2, k, m - 1, T, T2);
//     }
//     else {
//         // ds = k from construction
//         // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
//         auto scopy = s2;
//         scopy.resize(k);
//         if (Degree(scopy) > 0) {
//             std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
//             std::vector<double> weights(Degree(scopy));

//             for (uint32_t i = 0; i < Degree(scopy); i++) {
//                 ctxs[i]    = T[i];
//                 weights[i] = s2[i + 1];
//             }

//             su = cc->EvalLinearWSumMutable(ctxs, weights);
//             // the highest order coefficient will always be 1 because s2 is monic.
//             cc->EvalAddInPlace(su, T[k - 1]);
//         }
//         else {
//             su = T[k - 1];
//         }

//         // adds the free term (at x^0)
//         cc->EvalAddInPlace(su, s2.front() / 2);
//         // The number of levels of su is the same as the number of levels of T[k-1] + 1.
//         // Will only get here when m = 2, so need to reduce the number of levels by 1.
//     }

//     // TODO : Andrey : here is different from 895 line
//     // Reduce number of levels of su to number of levels of T2km1.
//     //  cc->LevelReduceInPlace(su, nullptr);

//     Ciphertext<DCRTPoly> result;

//     if (flag_c) {
//         result = cc->EvalAdd(T2[m - 1], cu);
//     }
//     else {
//         result = cc->EvalAdd(T2[m - 1], divcs->q.front() / 2);
//     }

//     result = cc->EvalMult(result, qu);
//     cc->ModReduceInPlace(result);

//     cc->EvalAddInPlace(result, su);
//     cc->EvalSubInPlace(result, T2km1);

//     return result;
// }

// /* Compute positive integers k,m such that n < k(2^m-1) and k close to sqrt(n/2) */
// std::vector<uint32_t> ComputeDegreesPS(const uint32_t n) {
//     if (n == 0) {
//         OPENFHE_THROW(math_error, "ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");
//     }

//     std::vector<uint32_t> klist;
//     std::vector<uint32_t> mlist;

//     double sqn2 = sqrt(n / 2);

//     for (uint32_t k = 1; k <= n; k++) {
//         for (uint32_t m = 1; m <= ceil(log2(n / k) + 1) + 1; m++) {
//             if (int32_t(n - k * ((1 << m) - 1)) < 0) {
//                 if ((static_cast<double>(k - sqn2) >= -2) && ((static_cast<double>(k - sqn2) <= 2))) {
//                     klist.push_back(k);
//                     mlist.push_back(m);
//                 }
//             }
//         }
//     }

//     uint32_t minIndex = std::min_element(mlist.begin(), mlist.end()) - mlist.begin();

//     return std::vector<uint32_t>{{klist[minIndex], mlist[minIndex]}};
// }

// /* f and g are vectors of Chebyshev interpolation coefficients of the two polynomials.
// We assume their dominant coefficient is not zero. LongDivisionChebyshev returns the
// vector of Chebyshev interpolation coefficients for the quotient and remainder of the
// division f/g. longDiv is a struct that contains the vectors of coefficients for the
// quotient and rest. We assume that the zero-th coefficient is c0, not c0/2 and returns
// the same format.*/
// std::shared_ptr<longDiv> LongDivisionChebyshev(const std::vector<double>& f, const std::vector<double>& g) {
//     uint32_t n = Degree(f);
//     uint32_t k = Degree(g);

//     if (n != f.size() - 1) {
//         OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divident is zero.");
//     }

//     if (k != g.size() - 1) {
//         OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divisor is zero.");
//     }

//     std::vector<double> q;
//     std::vector<double> r = f;

//     if (int32_t(n - k) >= 0) {
//         std::vector<double> q2(n - k + 1, 0.0);
//         q = q2;

//         while (int32_t(n - k) > 0) {
//             q[n - k] = 2 * r.back();
//             if (IsNotEqualOne(g[k])) {
//                 q[n - k] /= g.back();
//             }

//             std::vector<double> d(n + 1, 0.0);

//             if (int32_t(k) == int32_t(n - k)) {
//                 d.front() = 2 * g[n - k];

//                 for (uint32_t i = 1; i < 2 * k + 1; i++) {
//                     d[i] = g[abs(int32_t(n - k - i))];
//                 }
//             }
//             else {
//                 if (int32_t(k) > int32_t(n - k)) {
//                     d.front() = 2 * g[n - k];
//                     for (uint32_t i = 1; i < k - (n - k) + 1; i++) {
//                         d[i] = g[abs(int32_t(n - k - i))] + g[int32_t(n - k + i)];
//                     }

//                     for (uint32_t i = k - (n - k) + 1; i < n + 1; i++) {
//                         d[i] = g[abs(int32_t(i - n + k))];
//                     }
//                 }
//                 else {
//                     d[n - k] = g.front();
//                     for (uint32_t i = n - 2 * k; i < n + 1; i++) {
//                         if (i != n - k) {
//                             d[i] = g[abs(int32_t(i - n + k))];
//                         }
//                     }
//                 }
//             }

//             if (IsNotEqualOne(r.back())) {
//                 // d *= f[n]
//                 std::transform(d.begin(), d.end(), d.begin(),
//                                std::bind(std::multiplies<double>(), std::placeholders::_1, r.back()));
//             }
//             if (IsNotEqualOne(g.back())) {
//                 // d /= g[k]
//                 std::transform(d.begin(), d.end(), d.begin(),
//                                std::bind(std::divides<double>(), std::placeholders::_1, g.back()));
//             }

//             // f-=d
//             std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<double>());
//             if (r.size() > 1) {
//                 n = Degree(r);
//                 r.resize(n + 1);
//             }
//         }

//         if (n == k) {
//             q.front() = r.back();
//             if (IsNotEqualOne(g.back())) {
//                 q.front() /= g.back();  // q[0] /= g[k]
//             }
//             std::vector<double> d = g;
//             if (IsNotEqualOne(r.back())) {
//                 // d *= f[n]
//                 std::transform(d.begin(), d.end(), d.begin(),
//                                std::bind(std::multiplies<double>(), std::placeholders::_1, r.back()));
//             }
//             if (IsNotEqualOne(g.back())) {
//                 // d /= g[k]
//                 std::transform(d.begin(), d.end(), d.begin(),
//                                std::bind(std::divides<double>(), std::placeholders::_1, g.back()));
//             }
//             // f-=d
//             std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<double>());
//             if (r.size() > 1) {
//                 n = Degree(r);
//                 r.resize(n + 1);
//             }
//         }
//         q.front() *= 2;  // Because we want to have [c0] in the last spot, not [c0/2]
//     }
//     else {
//         std::vector<double> q2(1, 0.0);
//         q = q2;
//         r = f;
//     }

//     return std::make_shared<longDiv>(q, r);
// }


// Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
//                                                                const std::vector<double>& constants) const {
//     const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertexts[0]->GetCryptoParameters());

//     auto cc   = ciphertexts[0]->GetCryptoContext();
//     auto algo = cc->GetScheme();

//     if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
//         // Check to see if input ciphertexts are of same level
//         // and adjust if needed to the max level among them
//         uint32_t maxLevel = ciphertexts[0]->GetLevel();
//         uint32_t maxIdx   = 0;
//         for (uint32_t i = 1; i < ciphertexts.size(); i++) {
//             if ((ciphertexts[i]->GetLevel() > maxLevel) ||
//                 ((ciphertexts[i]->GetLevel() == maxLevel) && (ciphertexts[i]->GetNoiseScaleDeg() == 2))) {
//                 maxLevel = ciphertexts[i]->GetLevel();
//                 maxIdx   = i;
//             }
//         }

//         for (uint32_t i = 0; i < maxIdx; i++) {
//             algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
//         }

//         for (uint32_t i = maxIdx + 1; i < ciphertexts.size(); i++) {
//             algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
//         }

//         if (ciphertexts[maxIdx]->GetNoiseScaleDeg() == 2) {
//             for (uint32_t i = 0; i < ciphertexts.size(); i++) {
//                 algo->ModReduceInternalInPlace(ciphertexts[i], BASE_NUM_LEVELS_TO_DROP);
//             }
//         }
//     }

//     Ciphertext<DCRTPoly> weightedSum = cc->EvalMult(ciphertexts[0], constants[0]);

//     Ciphertext<DCRTPoly> tmp;
//     for (uint32_t i = 1; i < ciphertexts.size(); i++) {
//         tmp = cc->EvalMult(ciphertexts[i], constants[i]);
//         cc->EvalAddInPlace(weightedSum, tmp);
//     }

//     cc->ModReduceInPlace(weightedSum);

//     return weightedSum;
// }




int main() {
    double a = 0.0;  // Lower bound of the interval
    double b = 1073741824; // Upper bound of the interval
    uint32_t degree = 5; // Chosen degree for the approximation

    // Define the function f(x) = 1/x
    auto func = [](double x) { return 1/x; };

    // Calculate the Chebyshev coefficients
    std::vector<double> coefficients = EvalChebyshevCoefficients(func, a, b, degree);
    // Output the coefficients
    std::cout << "Chebyshev coefficients for f(x) = 1/x:" << std::endl;
    for (size_t i = 0; i < coefficients.size(); ++i) {
        std::cout << "Coefficient " << i << ": " << coefficients[i] << std::endl;
    }

    uint32_t deg = Degree1(coefficients);
    cout << "Degree of the polynomial: " << deg << endl;

    // testing inputs
    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(6);
    //parameters.SetScalingModSize(90);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x = {1, 5, 10, 20, 100, 500, 800, 1000000000};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto input_cipher = cc->Encrypt(keys.publicKey, ptxt);


    Ciphertext<DCRTPoly> result = EvalChebyshevSeriesLinear1(input_cipher, coefficients, a, b, keys);
    

    Plaintext pt;
    cc->Decrypt(keys.secretKey, result, &pt);
    const std::vector<double> &vec_result = pt->GetRealPackedValue();

    //  uint32_t precision =
    //     std::floor(CalculateApproximationError(pt1->GetCKKSPackedValue(), pt->GetCKKSPackedValue()));
    // std::cout << "Bootstrapping precision after 1 iteration: " << precision << std::endl;

    std::cout << "\n";
    for (size_t i = 0; i < batchSize; i++) {
    std::cout << "Output after Cheby, result[" << i
              << "]:" << vec_result[i] << std::endl;
    }

    return 0;
}
