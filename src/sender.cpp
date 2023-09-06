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
using namespace std::chrono;
using namespace lbcrypto;

const static unsigned int POLYNOMIAL_APPROX_DEG = 27; //was 13
const static unsigned int MAX_ITEM_DIFFERENCE = 1 << 30;

void printUsage() {
  cout << "Options:" << endl;
  cout << "  -c   CryptoContext file" << endl;
  cout << "  -p   Public key file" << endl;
  cout << "  -e   Evaluation keys file" << endl;
  cout << "  -t  Scheme (BFV (default) or CKKS)" << endl;
  cout << "  -s  A power to include" << endl;
  cout << "  -n  The number of ciphertexts" << endl;
  cout << "  -l  Low degree for Paterson-Stockmeyer (leave unspecified to use "
          "naive dot polynomial evaluation)"
       << endl;
  cout << "  -m  File containing sender inputs" << endl;
}

int main(int argc, char **argv) {
  high_resolution_clock::time_point start, end;

  string contextFile;
  string publicKeyFile;
  string evalKeysFile;
  string privateKeyFile =
      ""; // Sender doesn't use a private key, so this is a dummy argument

  set<unsigned int> window_powers;
  window_powers.insert(1);

  bool finite_field = true;
  unsigned int ps_low_degree = 0;
  string sender_poly_filename = "";

  // Parse command-line arguments using GNU getopt
  int opt;
  while ((opt = getopt(argc, argv, "c:p:e:qt:s:l:m:r:")) != -1) {
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
    case 'l': {
      ps_low_degree = atoi(optarg);
      break;
    }
    case 'm': {
      sender_poly_filename = optarg;
      break;
    }
  case 'r':{
      privateKeyFile = optarg;
      break;
  }
    default:
      printUsage();
      return 1;
    }
  }

  if (contextFile.empty() || publicKeyFile.empty() || evalKeysFile.empty() ||
      sender_poly_filename.empty()) {
    cout << "Missing file arguments." << endl;
    printUsage();
    return 1;
  }
  //Warn about SK - can take this out
  /*
  if(privateKeyFile != ""){
    cerr << "\tWarning: private key argued, this implementation is insecure and should only be used for debugging/demo purposes: " << privateKeyFile << endl;
  }
  */

  // Deserialize the objects and obtain the CryptoContext
  KeyPair<DCRTPoly> keyPair;
  CryptoContext<DCRTPoly> cryptoContext;
  deserializeObjects(contextFile, publicKeyFile, privateKeyFile, evalKeysFile,
                     cryptoContext, keyPair);

  ifstream sender_fstream(sender_poly_filename);
  size_t num_objects = 0;
  sender_fstream.read((char *)&num_objects, sizeof(num_objects));
  assert(num_objects);

  Ciphertext<DCRTPoly> result;
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();

  /*
  if (sender_inputs.size() % batchsize) {
    sender_inputs.resize(sender_inputs.size() +
                             (sender_inputs.size() % batchsize),
                         DUMMY); // Pad with dummy inputs
  }
  */

  if (finite_field) {
    start = high_resolution_clock::now();
    vector<Plaintext> sender_poly(num_objects);
    vector<vector<int64_t>> sender_poly_vec(num_objects);
    // TODO read this in from a file
    for (size_t i = 0; i < num_objects; i++) {
      size_t sz = -1;
      sender_fstream.read((char *)&sz, sizeof(sz));
      sender_poly_vec[i].resize(sz);
      for (size_t j = 0; j < sz; j++) {
        sender_fstream.read((char *)&(sender_poly_vec[i][j]), sizeof(int64_t));
      }
      sender_poly[i] = cryptoContext->MakePackedPlaintext(sender_poly_vec[i]);
    }

    // Set up DAG
    // Easier to do this after we've constructed the sender polynomial
    PowersDag dag;
    std::set<unsigned int> target_powers;
    for (unsigned int i = 1; i < sender_poly.size(); i++) {
      target_powers.insert(i);
    }
    // Trim extra source powers if targets don't contain sources
    trim_sources(window_powers, target_powers);
    if (!dag.configure(window_powers, target_powers)) {
      cerr << "Failed to configure!\n";
      return 1;
    }

    // Read ciphertexts from stdin
    vector<Ciphertext<DCRTPoly>> ctexts(target_powers.size());
    for (const unsigned int i : window_powers) {
      if (i - 1 < sender_poly.size()) {
        Serial::Deserialize(ctexts.at(i - 1), std::cin, SerType::BINARY);
      }
    }
    // Compute powers
    compute_all_powers(dag, ctexts, cryptoContext);
    // Evaluate sender polynomial
    if (ps_low_degree > 1 && ps_low_degree < sender_poly.size()) {
      result = eval_sender_poly_PS(ctexts, sender_poly, cryptoContext,
                                   ps_low_degree);
    } else {
      result = eval_sender_poly_dot(ctexts, sender_poly, cryptoContext);
    }

    // Multiply by random finite field element
    uint64_t plain_modulus =
        cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(
        0, plain_modulus - 1);
    vector<int64_t> rand_vector(batchsize);
#pragma omp parallel for
    for (size_t i = 0; i < rand_vector.size(); i++) {
      rand_vector[i] =
          dist(rng) %
          plain_modulus; // Second modular reduction here should be unnecessary,
                         // but the uniform_int_distribution isn't properly
                         // enforcing the range
    }
    Plaintext rand_pt = cryptoContext->MakePackedPlaintext(rand_vector);
    result = cryptoContext->EvalMult(result, rand_pt);
    end = high_resolution_clock::now();
    std::cerr << "\tAPSI query time (data at site not encrypted): " << duration_cast<chrono::milliseconds>(end-start).count() << "ms" << std::endl;
  } else {
    // New method
    Ciphertext<DCRTPoly> query_ctext;
    start = high_resolution_clock::now();
    Serial::Deserialize(query_ctext, std::cin, SerType::BINARY);
    end = high_resolution_clock::now();
    std::cerr << "\tReading in query: " << duration_cast<chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    //DEBUG
    /*
    if(privateKeyFile != ""){
      Plaintext pt;
      cryptoContext->Decrypt(keyPair.secretKey, query_ctext, &pt);
      for(const auto & x : pt->GetCKKSPackedValue()){
        assert(!(x != x));
      }
    }
    */

    // CKKS encoding is done in ckks_encode() in new_psi.h
    vector<Ciphertext<DCRTPoly>> sender_ckks_inputs(num_objects);
    if(num_objects != 1){
      std::cerr << "\tWARNING: more than 1 sender ciphertext" << std::endl;
    }
    start = high_resolution_clock::now();
    for (size_t i = 0; i < num_objects; i++) {
      Serial::Deserialize(sender_ckks_inputs[i], sender_fstream, SerType::BINARY);
    }
    end = high_resolution_clock::now();
    std::cerr << "\tReading in database: " << duration_cast<chrono::milliseconds>(end-start).count() << "ms" << std::endl;
    
    //DEBUG
    /*
    if(privateKeyFile != ""){
      Plaintext pt;
      cryptoContext->Decrypt(keyPair.secretKey, query_ctext, &pt);
      cerr << "Query: " << pt << endl;
      cryptoContext->Decrypt(keyPair.secretKey, sender_ckks_inputs[0], &pt);
      cerr << "Sender: " << pt << endl;
    }
    */
    cerr << "\tStarting query..." << endl;
    start = high_resolution_clock::now();
    result =
        query_sender_batched(sender_ckks_inputs, query_ctext, cryptoContext,
                             POLYNOMIAL_APPROX_DEG, 0, MAX_ITEM_DIFFERENCE
                             , keyPair.secretKey
                             );
    end = high_resolution_clock::now();
    std::cerr << "\tEncrypted query: " << duration_cast<chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    //DEBUG
    /*
    if(privateKeyFile != ""){
      Plaintext pt;
      cryptoContext->Decrypt(keyPair.secretKey, result, &pt);
      //cerr << "Result: " << pt << endl;
      for(const auto & x : pt->GetCKKSPackedValue()){
        assert(!(x != x));
      }
    }    
    */
  }

  // Write result to stdout
  Serial::Serialize(result, std::cout, SerType::BINARY);

  return 0;
}
