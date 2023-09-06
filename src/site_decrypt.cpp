#include <algorithm>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <random>
#include <set>

#include <openfhe.h>
// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "../include/basic_psi.h"
#include "../include/new_psi.h"
#include "../include/powers.h"
#include "../include/utilities.h"

using namespace std;
using namespace lbcrypto;

const static unsigned int POLYNOMIAL_APPROX_DEG = 13;
const static unsigned int MAX_ITEM_DIFFERENCE = 1 << 30;

void printUsage() {
  cout << "Options:" << endl;
  cout << "  -c   CryptoContext file" << endl;
  cout << "  -p   Public key file" << endl;
  cout << "  -e   Evaluation keys file" << endl;
  cout << "  -t  Scheme (BFV (default) or CKKS)" << endl;
  cout << "  -r  A secret key" << endl;
  cout << "  -n  Party number (default 0, nontriviality of argument controls "
          "which MultipartyDecrypt function is used)"
       << endl;
}

// TODO functionality for aggregation before decryption
// Do this in a separate file
int main(int argc, char **argv) {
  string contextFile;
  string publicKeyFile;
  string evalKeysFile;
  string privateKeyFile = "";

  unsigned int party_num = 0;

  // Parse command-line arguments using GNU getopt
  int opt;
  while ((opt = getopt(argc, argv, "c:p:e:n:r:")) != -1) {
    switch (opt) {
    case 'c':
      contextFile = optarg;
      break;
    case 'p':
      publicKeyFile = optarg;
      break;
    case 'e':
      evalKeysFile = optarg;
      break;
    case 'n': {
      party_num = atoi(optarg);
      break;
    }
    case 'r': {
      privateKeyFile = optarg;
      break;
    }
    default:
      printUsage();
      return 1;
    }
  }

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

  Ciphertext<DCRTPoly> ct_in;
  Serial::Deserialize(ct_in, std::cin, SerType::BINARY);

  auto ciphertextPartial =
      !party_num
          ? cryptoContext->MultipartyDecryptLead({ct_in}, keyPair.secretKey)
          : cryptoContext->MultipartyDecryptMain({ct_in}, keyPair.secretKey);

  // IMPORTANT: Need to only output first component here
  Serial::Serialize(ciphertextPartial[0], std::cout, SerType::BINARY);

  return 0;
}
