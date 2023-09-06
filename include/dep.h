#ifndef DEP_H
#define DEP_H

#include <cassert>
#include <cmath>
#include <functional>

#include <openfhe.h>

using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;

double default_cheb(const double d) { return 1 / (d * d + 1); }

Ciphertext<DCRTPoly> DEP(const Ciphertext<DCRTPoly> &y, const double L,
                         const double R, const int i,
                         const CryptoContext<DCRTPoly> &cryptoContext) {
  assert(i >= 0);
  double coeff = 4 / (R * R * 27 * pow(L, (double)i * 2));
  // May need to replace these with Eval calls
  auto y3 = y * y;
  y3 *= y;
  y3 = cryptoContext->EvalMult(y3, coeff);
  return y - y3;
}

Ciphertext<DCRTPoly>
extended_function(const double L, const double R, const int n,
                  const Ciphertext<DCRTPoly> &x,
                  const CryptoContext<DCRTPoly> &cryptoContext,
                  const std::function<double(double)> &P = default_cheb) {
  // Copies x - maybe look into clobbering instead of copying
  auto y = x;
  for (int i = n - 1; i; i--) {
    y = DEP(y, L, R, i, cryptoContext);
  }
  y = cryptoContext->EvalMult(y, 1 / R);
  auto y2 = y * y;
  auto y3 = y2 * y;
  auto y5 = y2 * y3;
  double frac = ((4 * L * L * (pow(L, (double)n * 2) - 1)) /
                 (27 * pow(L, (double)n * 2) * ((L * L) - 1)));
  auto second_approx_y = y3 - y5;
  second_approx_y = cryptoContext->EvalMult(second_approx_y, frac);
  second_approx_y += y;
  return cryptoContext->EvalChebyshevFunction(
      P, second_approx_y, -R, R, 5); // Chebyshev degree is hardcoded for now
}

#endif