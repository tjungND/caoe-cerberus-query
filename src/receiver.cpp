#include <fstream>
#include <getopt.h>
#include <iostream>
#include <openfhe.h>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "scheme/bfvrns/bfvrns-multiparty.h"
#include "scheme/ckksrns/ckksrns-multiparty.h"

#include "../include/basic_psi.h"
#include "../include/new_psi.h"
#include "../include/utilities.h"

using namespace std;
using namespace lbcrypto;

void printUsage() {
  cout << "Options:" << endl;
  cout << "  -c   CryptoContext file" << endl;
  cout << "  -p   Public key file" << endl;
  cout << "  -r  Private key file" << endl;
  cout << "  -e   Evaluation keys file" << endl;
  cout << "  -r  Whether we're querying (default) or receiving results" << endl;
  cout << "  -t  Scheme (BFV or CKKS)" << endl;
  cout << "  -s  A power to include" << endl;
  cout << "  -q  Whether to make (default) or decrypt a query" << endl;
}

int main(int argc, char **argv) {
  string contextFile;
  string publicKeyFile;
  string privateKeyFile;
  string evalKeysFile;

  set<unsigned int> window_powers;
  window_powers.insert(1);

  unsigned int num_ciphertexts = 1;

  bool query_mode = true;
  bool finite_field = true;

  // Parse command-line arguments using GNU getopt
  int opt;
  while ((opt = getopt(argc, argv, "c:p:r:e:qt:s:n:")) != -1) {
    switch (opt) {
    case 'c':
      contextFile = optarg;
      break;
    case 'p':
      publicKeyFile = optarg;
      break;
    case 'r':
      privateKeyFile = optarg;
      break;
    case 'e':
      evalKeysFile = optarg;
      break;
    case 'q': {
      query_mode = !query_mode;
      break;
    }
    case 't': {
      finite_field = !strcmp(optarg, "BFV");
      break;
    }
    case 's': {
      window_powers.insert(atoi(optarg));
      break;
    }
    case 'n': {
      // Technically, this is arguing the number of ciphertexts too
      num_ciphertexts = atoi(optarg);
      break;
    }
    default:
      printUsage();
      return 1;
    }
  }

  assert(num_ciphertexts);

  if (contextFile.empty() || publicKeyFile.empty() || evalKeysFile.empty()) {
    cout << "Missing file arguments." << endl;
    printUsage();
    return 1;
  }

  // Deserialize the objects and obtain the CryptoContext
  KeyPair<DCRTPoly> keyPair;
  CryptoContext<DCRTPoly> cryptoContext;
  deserializeObjects(contextFile, publicKeyFile, privateKeyFile, evalKeysFile,
                     cryptoContext, keyPair);

  uint64_t plain_modulus =
      cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
  uint64_t temp_mod = 1;
  temp_mod = 1 << plain_modulus;
  if (!finite_field) {
    plain_modulus = temp_mod;
  }

  size_t batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();

  if (query_mode) {
    // First, encrypt input(s)
    // Read in all inputs from stdin
    // Assume numerical inputs
    // ONLY ONE USER VALUE (for sender-side batching and a single query)
    uint64_t user_val;
    cin >> user_val;

    if (finite_field) {
      assert(user_val != DUMMY);
    }
    vector<uint64_t> user_values(batchsize, user_val);

    if (user_values.size() > batchsize) {
      cout << "ERROR: more inputs than capacity" << endl;
      return 1;
    }

    if (finite_field) {
      // DEBUG
      /*
      for(const uint64_t x : user_values){
        std::cerr << x << endl;
      }
      std::cerr << endl;
      */

      vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>> ctexts =
          receiver_windowed_vals(user_values, window_powers, cryptoContext,
                                 keyPair.publicKey);
      // Now write to stdout
      // Ignore the power index
      for (const auto &x : ctexts) {
        Serial::Serialize(x.second, std::cout, SerType::BINARY);
      }
    } else {
      // CKKS-based encryption
      Ciphertext<DCRTPoly> ckks_ctext =
          encrypt_single_slots(user_val, cryptoContext, keyPair.publicKey);
      Serial::Serialize(ckks_ctext, std::cout, SerType::BINARY);
    }

  } else {
    // TODO handle multiple partition results?
    // Reading results from sender(s)
    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec(num_ciphertexts);
    for (unsigned int i = 0; i < num_ciphertexts; i++) {
      Serial::Deserialize(partialCiphertextVec[i], std::cin, SerType::BINARY);
    }

    unsigned int slots_used = 0; // May also need this for CKKS method
    if (finite_field) {
      std::ifstream slots_ifs(SLOTS_USED_FNAME);
      slots_ifs >> slots_used;
      slots_ifs.close();
      assert(slots_used);
    }

    vector<int> res; // Final results
    if (partialCiphertextVec.size() == 1) {
      // Single-ciphertext mode - insecure!
      assert(privateKeyFile != "");
      res = finite_field
                ? finite_field_result(partialCiphertextVec[0], cryptoContext,
                                      keyPair.secretKey, slots_used)
                : in_intersection(partialCiphertextVec[0], cryptoContext,
                                  keyPair.secretKey);
    } else {
      // Multiparty case
      Plaintext pt;
      cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &pt);
      res = finite_field ? finite_field_result(pt, cryptoContext, slots_used)
                         : in_intersection(pt, cryptoContext);
    }

    bool intersection = false;
    for (size_t i = 0; i < res.size(); i++) {
      if (res[i]) {
        intersection = true;
        break;
      }
    }
    cout << (intersection ? 1 : 0) << endl;

    /*
    if(!finite_field){
      cout << "CKKS method results: ";
      for(const int i : res){
        cout << i << ' ';
      }
      cout << endl;
    }
*/
  }

  return 0;
}
