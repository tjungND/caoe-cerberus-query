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

int main(int argc, char **argv) {
  string contextFile;
  string publicKeyFile;
  string evalKeysFile;
  string privateKeyFile = "";

  bool finite_field = true;
  set<unsigned int> window_powers;
  window_powers.insert(1);

  // Parse command-line arguments using GNU getopt
  int opt;
  while ((opt = getopt(argc, argv, "c:p:e:qt:s:")) != -1) {
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
    case 't': {
      finite_field = !strcmp(optarg, "BFV");
      break;
    }
    case 's': {
      window_powers.insert(atoi(optarg));
      break;
    }
    }
  }

  if (contextFile.empty() || publicKeyFile.empty() || evalKeysFile.empty()) {
    cout << "Missing file arguments." << endl;
    return 1;
  }

  // Deserialize the objects and obtain the CryptoContext
  KeyPair<DCRTPoly> keyPair;
  CryptoContext<DCRTPoly> cryptoContext;
  deserializeObjects(contextFile, publicKeyFile, privateKeyFile, evalKeysFile,
                     cryptoContext, keyPair);

  vector<uint64_t> sender_inputs;
  // Read sender input
  uint64_t sender_val;
  while (std::cin >> sender_val) {
    //assert(sender_val != DUMMY);
    sender_inputs.push_back(sender_val);
  }
  assert(sender_inputs.size());

  if (finite_field) {
    unsigned int slots_used = 0;
    vector<vector<int64_t>> sender_poly =
        sender_polynomial_batched(sender_inputs, cryptoContext, slots_used);
    std::ofstream slots_ofs(SLOTS_USED_FNAME);
    slots_ofs << slots_used;
    slots_ofs.close();

    size_t num_objects = sender_poly.size();
    std::cout.write((char *)&num_objects, sizeof(num_objects));

    for (vector<int64_t> &p : sender_poly) {
      size_t sz = p.size();
      std::cout.write((char *)&sz, sizeof(sz));
      for (const int64_t x : p) {
        std::cout.write((char *)&x, sizeof(x));
      }
    }
  } else {
    vector<Ciphertext<DCRTPoly>> sender_ckks_inputs =
        encrypt_batched(sender_inputs, cryptoContext, keyPair.publicKey);

    size_t num_objects = sender_ckks_inputs.size();
    std::cout.write((char *)&num_objects, sizeof(num_objects));

    for (const Ciphertext<DCRTPoly> &ct : sender_ckks_inputs) {
      Serial::Serialize(ct, std::cout, SerType::BINARY);
    }
  }

  return 0;
}