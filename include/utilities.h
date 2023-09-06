#ifndef UTILITIES_H
#define UTILITIES_H

#include <fstream>
#include <iostream>
#include <string>

#include <openfhe.h>
// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using std::string;
using namespace lbcrypto;

// Need to register Plaintext with Cereal - apparently not done in any included
// header files
CEREAL_REGISTER_POLYMORPHIC_RELATION(Plaintext, PlaintextImpl)

void deserializeObjects(const string &contextFile, const string &publicKeyFile,
                        const string &privateKeyFile,
                        const string &evalKeysFile,
                        CryptoContext<DCRTPoly> &cryptoContext,
                        KeyPair<DCRTPoly> &keyPair) {
  // Deserialize the CryptoContext
  if (!Serial::DeserializeFromFile(contextFile, cryptoContext,
                                   SerType::BINARY)) {
    std::cerr << "Error opening context file: " << contextFile << std::endl;
    exit(1);
  }

  // Deserialize the PK/SK
  // std::ifstream publicKeyFileStream(publicKeyFile, ios::binary);
  Serial::DeserializeFromFile(publicKeyFile, keyPair.publicKey,
                              SerType::BINARY);
  if (privateKeyFile != "") {
    Serial::DeserializeFromFile(privateKeyFile, keyPair.secretKey,
                                SerType::BINARY);
  }

  if (evalKeysFile != "") {
    std::ifstream evalKeysFileStream(evalKeysFile, std::ios::binary);
    cryptoContext->DeserializeEvalMultKey(evalKeysFileStream, SerType::BINARY);
  }
  return;
}

const unsigned int RATIONAL_K_FACTOR = 1 << 10;
const unsigned int RATIONAL_S_FACTOR = 1 << 4;

/*
const unsigned int RECEIVER_DUMMY = 0;
const unsigned int SENDER_DUMMY = 1;
*/
const uint64_t DUMMY = 0; // Only need a single dummy value if the receiver's
                          // data is fully-packed with a single value

const char *SLOTS_USED_FNAME = "slots_used.txt";

constexpr static double SPSI_SCALE = 2.5;
constexpr static double SPSI_THRESHOLD = pow(SPSI_SCALE, 4);

#endif
