#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include "../../include/new_psi.h"

// openFHE
#include "openfhe.h"
using lbcrypto::Ciphertext;
using lbcrypto::DCRTPoly;

using namespace lbcrypto;
using std::vector;


//data types we will need
using CT = Ciphertext<DCRTPoly> ; //ciphertext
using PT = Plaintext ; //plaintext
using vecCT = std::vector<CT>; //vector of ciphertexts
using vecPT = std::vector<PT>; //vector of plaintexts
using vecInt = std::vector<int64_t>; // vector of ints
using vecChar = std::vector<char>; // vector of characters




using namespace std;

int main() {

  uint32_t batchSize = 8;
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetMultiplicativeDepth(5);
  parameters.SetScalingModSize(50);
  parameters.SetBatchSize(batchSize);
  parameters.SetSecurityLevel(HEStd_128_classic);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

   // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
   cc->Enable(PKE);
   cc->Enable(KEYSWITCH);
   cc->Enable(LEVELEDSHE);
   cc->Enable(ADVANCEDSHE);
   cc->Enable(FHE);
   KeyPair<DCRTPoly> keyPair =  cc->KeyGen();

   cc->EvalMultKeysGen(keyPair.secretKey);

   int ringDim = cc->GetRingDimension();
   std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

   ///////-------------------------------------------------------------------------

   vector<CT> senderCTvec;
   vector<uint64_t> sender_vals = {10, 10, 10, 10, 10, 10, 10, 10};
   PublicKey<DCRTPoly> pk = keyPair.publicKey;

   senderCTvec = sender_encrypt(sender_vals, cc, pk);


   PT result;
   std::cout.precision(8);

   std::cout << "Sender vals length: " << senderCTvec.size() << std::endl;

   cc->Decrypt(senderCTvec[1], keyPair.secretKey, &result);
   result->SetLength(batchSize);
   std::cout << "sender vals [1]: " << result << std::endl;
///////-------------------------------------------------------------------------

   CT receiverCT;
   vector<uint64_t> receiver_vals = {2, 10, 1, 1, 1, 1, 1, 1};
   receiverCT = receiver_encrypt(receiver_vals, cc, pk);

   std::cout << "Receiver vals length: " << std::endl;

   cc->Decrypt(receiverCT, keyPair.secretKey, &result);
   result->SetLength(batchSize);
   std::cout << "receiver vals " << result << std::endl;
   ///////-------------------------------------------------------------------------
   uint64_t plain_modulus = cc->GetCryptoParameters()
                                ->GetPlaintextModulus();
    PrivateKey<DCRTPoly> sk = keyPair.secretKey;
    std::cout << "plaintext mod: " << plain_modulus << std::endl;
    CT queryCT = query(senderCTvec, receiverCT, cc, 1024, 16, 6, 1 << 2);


    cc->Decrypt(queryCT, sk, &result);
    std::cout << "queryCT after query function: " << result << std::endl;

    vector<int> in_inters = in_intersection(queryCT, 1024, cc, sk);

   std::cout << "Intersection results: " << std::endl;
    for (size_t i = 0; i < in_inters.size(); i++) {
   std::cout << in_inters[i] << " ";
   }
   std::cout << std::endl;


  return 0;
}
