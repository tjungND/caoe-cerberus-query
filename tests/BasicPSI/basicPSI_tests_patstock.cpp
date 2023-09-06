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
  parameters.SetMultiplicativeDepth(7);
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

  // unsigned int num_sender_vals = 8;

  // std::vector<uint64_t> sender_vals{};
  /*
  unsigned int unique_args = 2;
  for(size_t i = 0; i < sender_vals.size(); i++){
    sender_vals[i] = i;
  }
  */
  // uint64_t plain_modulus = cryptoContext->GetCryptoParameters()
  //                             ->GetPlaintextModulus();

  vector<uint64_t> matching_poly = {1, 2,  3,  4,  5,  6,  7, 8,
                                    9, 10, 11, 12, 13, 14, 15};
  // vector<PT> plain_sender_poly = sender_polynomial(sender_vals,
  // cryptoContext); vecPT sender_poly_plaintexts =
  // sender_polynomial(sender_vals, cryptoContext);
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  vecPT sender_poly_plaintexts(matching_poly.size());

  for (unsigned int i = 0; i < matching_poly.size(); i++) {
    vector<int64_t> v(batchsize, matching_poly[i]);
    sender_poly_plaintexts[i] = cryptoContext->MakePackedPlaintext(v);
  }

  std::vector<uint64_t> receiver_vals = {0, 1, 2, 4};
  CT receiverCT;

  std::set<unsigned int> source_powers{1, 2, 4};

  vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>> query_ciphertexts =
      receiver_windowed_vals(
          receiver_vals, source_powers, cryptoContext,
          pk); // check if it contains the ciphertext with // first element: 6
               // -5 1 and second one 36 25 1

  unsigned int ps_low_degree = 3;

  PowersDag dag;
  std::set<unsigned int> target_powers;
  // TODO make function to insert the P-S powers
  for (unsigned int i = 1; i <= ps_low_degree; i++) {
    target_powers.insert(i);
  }
  unsigned int degree = matching_poly.size() - 1;
  unsigned int ps_high_degree = ps_low_degree + 1;
  for (unsigned int i = ps_high_degree; i <= degree; i += ps_high_degree) {
    target_powers.insert(i);
  }
  // for (unsigned int i = 1; i < sender_poly_plaintexts.size(); i++) {
  //   target_powers.insert(i);
  // }
  dag.configure(source_powers, target_powers);

  // First, read all powers from querier
  // Query must contain a series of (power, ct)
  // For CKKS-based PSI, this will be (1, ct)
  vector<Ciphertext<DCRTPoly>> query_ct_powers;
  query_ct_powers.resize(matching_poly.size() - 1);

  for (const unsigned int i : source_powers) {
    for (size_t j = 0; j < query_ciphertexts.size(); j++) {
      if (j >= query_ciphertexts.size()) {
        // We don't need this power, and don't have room for it, so just skip it
        break;
      }
      if (query_ciphertexts[j].first != i) {
        continue;
      } else {
        query_ct_powers.at(i - 1) = query_ciphertexts[j].second;
        std::cout << "Assigned power " << i << " to index " << i - 1
                  << std::endl;
        break;
      }
    }
  }

  // Now, compute the powers
  cout << "Powers:\n";
  std::set<unsigned int> computed_powers =
      compute_all_powers(dag, query_ct_powers, cryptoContext);
  for (const unsigned int p : computed_powers) {
    cout << p << ' ';
  }
  cout << endl;

  Ciphertext<DCRTPoly> query_result = eval_sender_poly_PS(
      query_ct_powers, sender_poly_plaintexts, cryptoContext, ps_low_degree);

  Plaintext pt1;
  cryptoContext->Decrypt(sk, query_result, &pt1);
  // std::cout<< "plaintext length: " << pt->GetLength() << std::endl;
  vector<int64_t> dec = pt1->GetPackedValue();
  for (size_t i = 0; i < 10; i++) {
    std::cout << "from patstock query_result[" << i << "]:" << dec[i]
              << std::endl;
  }

  vector<int> res = finite_field_result(query_result, cryptoContext, sk);

  for (size_t i = 0; i < receiver_vals.size(); i++) {
    std::cout << "Result[" << i << "]:" << res[i] << std::endl;
  }

  return 0;
}
