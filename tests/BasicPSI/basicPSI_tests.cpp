#include "../../include/basic_psi.h"
#include "../../include/powers.h"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>

// openFHE
#include "openfhe.h"
using lbcrypto::Ciphertext;
using lbcrypto::DCRTPoly;

using namespace lbcrypto;
using std::vector;

// data types we will need
using CT = Ciphertext<DCRTPoly>;     // ciphertext
using PT = Plaintext;                // plaintext
using vecCT = std::vector<CT>;       // vector of ciphertexts
using vecPT = std::vector<PT>;       // vector of plaintexts
using vecInt = std::vector<int64_t>; // vector of ints
using vecChar = std::vector<char>;   // vector of characters

using namespace std;

int main() {

  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetPlaintextModulus(536903681);
  parameters.SetMultiplicativeDepth(5);
  parameters.SetMaxRelinSkDeg(3);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  // enable features that you wish to use
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);

  auto keyPair = cryptoContext->KeyGen();
  PublicKey<DCRTPoly> pk = keyPair.publicKey;
  PrivateKey<DCRTPoly> sk = keyPair.secretKey;
  cryptoContext->EvalMultKeyGen(sk);

  std::vector<uint64_t> sender_vals = {1, 2,  3,  4,  5,  6,  7, 8,
                                       9, 10, 11, 12, 13, 14, 15};
  // uint64_t plain_modulus = cryptoContext->GetCryptoParameters()
  //                           ->GetPlaintextModulus();

  // vector<PT> plain_sender_poly = sender_polynomial(sender_vals,
  // cryptoContext);

  std::vector<uint64_t> receiver_vals = {0, 1, 2, 4};
  CT receiverCT;

  std::set<unsigned int> source_powers;
  source_powers.insert(1);
  source_powers.insert(2);
  source_powers.insert(3);
  source_powers.insert(4);

  vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>> query_ciphertexts =
      receiver_windowed_vals(
          receiver_vals, source_powers, cryptoContext,
          pk); // check if it contains the ciphertext with // first element: 6
               // -5 1 and second one 36 25 1

  Plaintext pt1;
  cryptoContext->Decrypt(sk, query_ciphertexts[1].second, &pt1);
  // std::cout<< "plaintext length: " << pt->GetLength() << std::endl;
  vector<int64_t> dec1 = pt1->GetPackedValue();
  for (int i = 0; i < 10; i++) {
    std::cout << "Query_ciphertexts[" << i << "]:" << dec1[i] << std::endl;
  }

  vecPT sender_poly_plaintexts = sender_polynomial(sender_vals, cryptoContext);

  PowersDag dag;
  std::set<unsigned int> target_powers;
  for (unsigned int i = 1; i < sender_poly_plaintexts.size(); i++) {
    target_powers.insert(i);
  }
  dag.configure(source_powers, target_powers);

  // First, read all powers from querier
  // Query must contain a series of (power, ct)
  // For CKKS-based PSI, this will be (1, ct)
  vector<Ciphertext<DCRTPoly>> query_ct_powers;
  query_ct_powers.resize(target_powers.size());

  for (const unsigned int i : source_powers) {
    query_ct_powers[i - 1] = query_ciphertexts[i - 1].second;
  }

  // Now, compute the powers
  compute_all_powers(dag, query_ct_powers, cryptoContext);

  Ciphertext<DCRTPoly> query_result = eval_sender_poly_dot(
      query_ct_powers, sender_poly_plaintexts, cryptoContext);

  Plaintext pt11;
  cryptoContext->Decrypt(sk, query_result, &pt11);
  // std::cout<< "plaintext length: " << pt->GetLength() << std::endl;
  vector<int64_t> dec = pt11->GetPackedValue();
  for (size_t i = 0; i < 10; i++) {
    std::cout << "from eval_sender_poly_dot query_result[" << i
              << "]:" << dec[i] << std::endl;
  }

  vector<int> res = finite_field_result(query_result, cryptoContext, sk);

  for (unsigned int i = 0; i < receiver_vals.size(); i++) {
    std::cout << "Result[" << i << "]:" << res[i] << std::endl;
  }

  return 0;
}
