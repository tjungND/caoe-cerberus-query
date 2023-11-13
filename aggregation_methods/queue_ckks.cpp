// this file was used to get the aggregation results for CKKS-based method

#include <algorithm>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <random>
#include <set>
#include <thread>
#include <mutex>
#include <forward_list>
#include <queue>


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
using namespace std::chrono;
using namespace lbcrypto;

const static unsigned int POLYNOMIAL_APPROX_DEG = 13;
const static unsigned int MAX_ITEM_DIFFERENCE = 1 << 30;
std::mutex flistMutex;

void processCiphertext1(unsigned int i, const std::vector<std::string> &input_ciphertext_filenames, CryptoContext<DCRTPoly> cryptoContext, std::queue<Ciphertext<DCRTPoly>> &fqueue) {
    std::ifstream ifs(input_ciphertext_filenames[i]);
    
    // Deserialize into tempCiphertext
    Ciphertext<DCRTPoly> tempCiphertext;
    Serial::Deserialize(tempCiphertext, ifs, SerType::BINARY);
    fqueue.push(tempCiphertext);
    ifs.close();

}



void printUsage() {
  cout << "Options:" << endl;
  cout << "  -c   CryptoContext file" << endl;
  cout << "  -p   Public key file" << endl;
  cout << "  -e   Evaluation keys file" << endl;
  cout << "  -t  Scheme (BFV (default) or CKKS)" << endl;
  cout << "  -r  A secret key" << endl;
}

// TODO functionality for aggregation before decryption
// Do this in a separate file
int main(int argc, char **argv) {
  high_resolution_clock::time_point start, end;
  string contextFile;
  string publicKeyFile;
  string evalKeysFile;
  string privateKeyFile = "";

  unsigned int num_ciphertexts = 1;
  bool finite_field = true;

  // Parse command-line arguments using GNU getopt
  int opt;
  while ((opt = getopt(argc, argv, "c:p:e:t:m:r:")) != -1) {
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
    case 'm': {
      num_ciphertexts = atoi(optarg);
      break;
    }
    case 'r':{
      privateKeyFile = optarg;
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

  vector<string> input_ciphertext_filenames;
  input_ciphertext_filenames.reserve(num_ciphertexts);
  vector<Ciphertext<DCRTPoly>> ciphertexts(num_ciphertexts);
  string fname;
  while(cin >> fname){
    input_ciphertext_filenames.push_back(fname);
  }
  assert(input_ciphertext_filenames.size() == num_ciphertexts);

  start = high_resolution_clock::now();
  Ciphertext<DCRTPoly> tempCiphertext;
  Ciphertext<DCRTPoly> resultCt;

  std::vector<double> resultvec(cryptoContext->GetEncodingParams()->GetBatchSize(), 0.0);
  Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(resultvec);
  resultCt = cryptoContext->Encrypt(keyPair.publicKey, pt);
  

std::queue<Ciphertext<DCRTPoly>> fqueue;


#pragma omp parallel for
for (unsigned int i = 0; i < num_ciphertexts; i++) {
    processCiphertext1(i, input_ciphertext_filenames, cryptoContext, fqueue);

    #pragma omp critical
    {
      if (!fqueue.empty()){
        cryptoContext->EvalAddInPlace(resultCt, fqueue.front());
        fqueue.pop();
      }
    }


}


  end = high_resolution_clock::now();
  std::cerr << "\tReading in per-site results from " << num_ciphertexts << " users: " << duration_cast<chrono::milliseconds>(end-start).count() << "ms" << std::endl;

  start = high_resolution_clock::now();
  Ciphertext<DCRTPoly> result = finite_field
                                    ? cryptoContext->EvalMultMany(ciphertexts)
                                    : resultCt;
  end = high_resolution_clock::now();
  std::cerr << "\tAggregating: " << duration_cast<chrono::milliseconds>(end-start).count() << "ms" << std::endl;                                    

  if(privateKeyFile != ""){
      Plaintext pt;
      cryptoContext->Decrypt(keyPair.secretKey, result, &pt);
      //cerr << "Result: " << pt << endl;
      for(const auto & x : pt->GetCKKSPackedValue()){
        assert(!(x != x));
      }
    }

  Serial::Serialize(result, std::cout, SerType::BINARY);

  return 0;
}


