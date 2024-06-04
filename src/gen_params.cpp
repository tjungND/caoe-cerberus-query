#include <cassert>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <cmath>
#include <openfhe.h>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace std;
using namespace lbcrypto;

void printUsage() {
  cout << "Usage: -d <computation_depth> -s "
          "<plaintext_space/precision> -t <scheme_type>"
       << endl;
  cout << "Options:" << endl;
  cout << "  -d, --depth    Computation depth" << endl;
  cout << "  -s, --space    Plaintext space (BFV) or precision (CKKS)" << endl;
  cout << "  -t, --type     Scheme type: BFV or CKKS" << endl;
}

int main(int argc, char **argv) {
  int computationDepth = 0;
  int plaintextSpace = 0;
  lbcrypto::SCHEME schemeType = BFVRNS_SCHEME;
  string folder = "./";
  unsigned int num_parties = 1;

  // Parse command-line arguments using GNU getopt
  int opt;
  while ((opt = getopt(argc, argv, "d:s:t:f:p:")) != -1) {
    switch (opt) {
    case 'd': {
      computationDepth = stoi(optarg);
      break;
    }
    case 's': {
      plaintextSpace = stoi(optarg);
      break;
    }
    case 'f': {
      folder = optarg;
      break;
    }
    case 'p': {
      num_parties = atoi(optarg);
      break;
    }
    case 't': {
      if (strcmp(optarg, "BFV") == 0) {
        schemeType = BFVRNS_SCHEME;
      } else if (strcmp(optarg, "CKKS") == 0) {
        schemeType = CKKSRNS_SCHEME;
      } else {
        cout << "Invalid scheme type. Supported types are BFV and CKKS."
             << endl;
        cout << "Argument: " << optarg << endl;
        printUsage();
        return 1;
      }
      break;
    }

    default: {
      printUsage();
      return 1;
    }
    }
  }

  assert(num_parties);

  if (computationDepth <= 1 || plaintextSpace <= 1) {
    cerr << "Invalid computation depth or plaintext space/precision." << endl;
    printUsage();
    return 1;
  }

  // Initialize OpenFHE
  CryptoContext<DCRTPoly> cryptoContext;

  assert(plaintextSpace);

  // Generate FHE parameters and setup the context
  if (schemeType == CKKSRNS_SCHEME) {
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetExecutionMode(EXEC_EVALUATION);
    parameters.SetMultiplicativeDepth(computationDepth);

    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(1 << 16);
   // parameters.SetScalingModSize(45);

// the noise flooding presets are only for OpenFHE installed with 128-bit native size. For 64-bit native size, use s and noise as 30.
    
    int alpha = 1024;
    int s = 36;
    parameters.SetNumAdversarialQueries(alpha);
    parameters.SetStatisticalSecurity(s);
    parameters.SetThresholdNumOfParties(ceil(num_parties/2));

    // sigma (noise bits) = underroot(24 * N * alpha) * 2^(s/2), N is the ring-dimension of RLWE
    double noise = 34;  // originally 34, highest 42
    parameters.SetNoiseEstimate(noise);

    // We can set our desired precision for 128-bit CKKS only. For NATIVE_SIZE=64, we ignore this parameter.
    parameters.SetDesiredPrecision(10);
    parameters.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);

    cryptoContext = GenCryptoContext(parameters);

    std::cerr << std::endl;
    std::cerr << "CKKS parameters :::::::: " << parameters << std::endl;
    std::cerr << std::endl;

    std::cerr << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cerr << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cerr << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

  } else if (schemeType == BFVRNS_SCHEME) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(computationDepth);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetPlaintextModulus(65537); 
    parameters.SetThresholdNumOfParties(ceil(num_parties/2));

    cryptoContext = GenCryptoContext(parameters);
  } else {
    cerr << "Invalid scheme type. Supported types are BFV and CKKS." << endl;
    printUsage();
    return 1;
  }

  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);
  cryptoContext->Enable(MULTIPARTY);

  // Generate public and private keys
  auto keyPair = cryptoContext->KeyGen();
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Serialize the context, keys, and evaluation keys to separate files
  if (!folder.empty() && folder.back() != '/') {
    folder += '/';
  }
  string contextFname = folder + "context.bin";
  string pkFname = folder + "publickey.bin";

  string evkFname = folder + "evalkeys.bin";

  ofstream contextFile(contextFname, ios::binary);
  ofstream publicKeyFile(pkFname, ios::binary);
  // ofstream privateKeyFile(skFname, ios::binary);
  ofstream evalKeysFile(evkFname, ios::binary);

  if (contextFile && publicKeyFile && evalKeysFile) {
    Serial::Serialize(cryptoContext, contextFile, SerType::BINARY);
    Serial::Serialize(keyPair.publicKey, publicKeyFile, SerType::BINARY);
    // Serial::Serialize(keyPair.secretKey, privateKeyFile, SerType::BINARY);
    cryptoContext->SerializeEvalMultKey(evalKeysFile, SerType::BINARY);
  } else {
    cerr << "Error writing to output files." << endl;
    return 1;
  }

  // Generate and write out all secret keys
  for (unsigned int i = 0; i < num_parties; i++) {
    string multipartyKeyFileName =
        folder + "privatekey_" + std::to_string(i) + ".bin";
    if (i) {
      keyPair = cryptoContext->MultipartyKeyGen(keyPair.publicKey);
    }
    ofstream privateKeyFile(multipartyKeyFileName, ios::binary);
    Serial::Serialize(keyPair.secretKey, privateKeyFile, SerType::BINARY);
  }
  // Secret keys are now in path/privatekey_${i}.bin
  string skFname = folder + "privatekey_${i}.bin";

  contextFile.close();
  publicKeyFile.close();
  // privateKeyFile.close();
  evalKeysFile.close();

  uint64_t plain_modulus =
      cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
  uint64_t temp_mod = 1;
  temp_mod = 1 << plain_modulus;
  if (schemeType == CKKSRNS_SCHEME) {
    cout << temp_mod << endl;
  } else {
    cout << plain_modulus << endl;
  }
  cout << contextFname << endl;
  cout << pkFname << endl;
  cout << skFname << endl;
  cout << evkFname << endl;

  return 0;
}
