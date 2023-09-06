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
}

int main(int argc, char **argv) {
  string contextFile;
  string publicKeyFile;
  string privateKeyFile;
  string evalKeysFile;
  // Parse command-line arguments using GNU getopt
  
  bool finite_field = true;
  
  int opt;
  while ((opt = getopt(argc, argv, "c:p:r:t:e:")) != -1) {
    switch (opt) {
    case 'c':
      contextFile = optarg;
      break;
    case 'p':
      publicKeyFile = optarg;
      break;
    case 'e':{
      evalKeysFile = optarg; //Not actually used
      break;
    }  
    case 't': {
      finite_field = !strcmp(optarg, "BFV");
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

  size_t batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();

  Plaintext pt;
  if(finite_field){
    vector<int64_t> user_values(batchsize, 1); //TODO completely rename files/executables/etc. - zero_ct is now a misnomer
    pt = cryptoContext->MakePackedPlaintext(user_values);
  }
  else{
    vector<double> user_values(batchsize, 0);
    pt = cryptoContext->MakeCKKSPackedPlaintext(user_values);
  }

 Ciphertext<DCRTPoly> zero_ct = cryptoContext->Encrypt(keyPair.publicKey, pt);
 if(!finite_field){
   cryptoContext->LevelReduceInPlace(zero_ct, nullptr, 32); //Heuristic guess from the new_psi computation
 }  
  
  Serial::Serialize(zero_ct, std::cout, SerType::BINARY);

  return 0;
}
