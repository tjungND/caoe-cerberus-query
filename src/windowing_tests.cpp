#include <algorithm>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <random>
#include <set>
#include <chrono>

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

using measure_typ = std::chrono::milliseconds;

void printUsage() {
  cout << "Options:" << endl;
  cout << "  -c   CryptoContext file" << endl;
  cout << "  -p   Public key file" << endl;
  cout << "  -e   Evaluation keys file" << endl;
  cout << "  -t  Scheme (BFV (default) or CKKS)" << endl;
  cout << "  -s  A power to include" << endl;
  cout << "  -n  The number of ciphertexts" << endl;
  cout << "  -l  Low degree for Paterson-Stockmeyer (leave unspecified to use naive dot polynomial evaluation)" << endl;
  cout << "  -m  File containing sender inputs" << endl;
}

int main(int argc, char **argv) {

  steady_clock::time_point start, end;

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
  while ((opt = getopt(argc, argv, "c:p:e:qt:s:l:")) != -1) {
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

  unsigned int chebyshev_degree = 13;
  unsigned int num_sender_inputs_per_partition = 1000000;

  vector<uint64_t> sender_inputs(num_sender_inputs_per_partition, 2);

  Ciphertext<DCRTPoly> result;
  unsigned int batchsize = cryptoContext->GetEncodingParams()->GetBatchSize();
  unsigned int slots_used = 0;
  vector<Plaintext> sender_poly;
  if(finite_field){
    sender_poly = sender_polynomial_batched(sender_inputs, cryptoContext, slots_used);
  }
  else{
    sender_inputs.resize(sender_inputs.size() * chebyshev_degree, 2);
    sender_poly = encode_batched(sender_inputs, cryptoContext, keyPair.publicKey);
  }
      

  PowersDag dag;
  std::set<unsigned int> target_powers;
  for (unsigned int i = 1; i < (finite_field? sender_poly.size() : chebyshev_degree); i++) {
    target_powers.insert(i);
  }
  // Trim extra source powers if targets don't contain sources
  trim_sources(window_powers, target_powers);
  if (!dag.configure(window_powers, target_powers)) {
    cerr << "Failed to configure!\n";
    return 1;
  }

  //Get ciphertext powers
  vector<Ciphertext<DCRTPoly>> ctexts(target_powers.size());
  vector<int64_t> pt_vals(cryptoContext->GetEncodingParams()->GetBatchSize(), 3);
  for (const unsigned int i : window_powers) {
    if (i - 1 < sender_poly.size()) {
      Plaintext pt = cryptoContext->MakePackedPlaintext(pt_vals);
      ctexts.at(i - 1) = cryptoContext->Encrypt(keyPair.publicKey, pt);
    }
  }

  //TIME THIS
  //Compute powers
  //TODO need to double the time for computing x and y powers, and find the runtime for a C-C-P dot product
  start = steady_clock::now();
  compute_all_powers(dag, ctexts, cryptoContext);
  end = steady_clock::now();
  long double d = duration_cast<measure_typ>(end - start).count();
  cout << "compute_powers " << d << endl;

  start = steady_clock::now();
  result = eval_sender_poly_dot(ctexts, sender_poly, cryptoContext);
  end = steady_clock::now();
  d = duration_cast<measure_typ>(end - start).count();
  cout << "eval_poly " << d << endl;
  
  if(finite_field){
    start = steady_clock::now();
     uint64_t plain_modulus =
        cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, plain_modulus);
    vector<int64_t> rand_vector(batchsize);
#pragma omp parallel for    
    for(size_t i = 0; i < rand_vector.size(); i++){
      rand_vector[i] = dist(rng);
    }
    Plaintext rand_pt = cryptoContext->MakePackedPlaintext(rand_vector);
    result = cryptoContext->EvalMult(result, rand_pt);
    end = steady_clock::now();
    d = duration_cast<measure_typ>(end - start).count();
    cout << "mask " << d << endl;
  }
  else{
    //Additive aggregation
    vector<Ciphertext<DCRTPoly>> vals((num_sender_inputs_per_partition / batchsize) + 1, result);
    start = steady_clock::now();
    auto tmp = cryptoContext->EvalAddManyInPlace(vals);
    end = steady_clock::now();
    d = duration_cast<measure_typ>(end - start).count();
    cout << "additive_agg " << d << endl;
  }



  //TODO: time random multiplication and SPSI aggregation
  //TODO: compute communication overhead


  if (finite_field) {
    //Compute powers
    compute_all_powers(dag, ctexts, cryptoContext);
    //Evaluate sender polynomial
    if (ps_low_degree > 1 && ps_low_degree < sender_poly.size()) {
      result = eval_sender_poly_PS(ctexts, sender_poly, cryptoContext,
                                   ps_low_degree);
    } else {
      result = eval_sender_poly_dot(ctexts, sender_poly, cryptoContext);
    }

    // Multiply by random finite field element
    // WARNING: this is a REALLY bad way of getting randomness, TODO replace
    // with something secure for a real(istic) implementation
    uint64_t plain_modulus =
        cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, plain_modulus);
    vector<int64_t> rand_vector(batchsize);
#pragma omp parallel for    
    for(size_t i = 0; i < rand_vector.size(); i++){
      rand_vector[i] = dist(rng);
    }
    Plaintext rand_pt = cryptoContext->MakePackedPlaintext(rand_vector);
    result = cryptoContext->EvalMult(result, rand_pt);

  } else {
    // New method
    Ciphertext<DCRTPoly> query_ctext;
    Serial::Deserialize(query_ctext, std::cin, SerType::BINARY);
    // CKKS encoding is done in ckks_encode() in new_psi.h
    vector<Ciphertext<DCRTPoly>> sender_ckks_inputs =
        encrypt_batched(sender_inputs, cryptoContext, keyPair.publicKey);
    result =
        query_sender_batched(sender_ckks_inputs, query_ctext, cryptoContext,
                             POLYNOMIAL_APPROX_DEG, 0, MAX_ITEM_DIFFERENCE);
  }

  stringstream ss;
  // Write result to stdout
  Serial::Serialize(result, ss, SerType::BINARY);
  size_t ctext_size = ss.str().size();
  cout << "result_size " << ctext_size << endl;

  return 0;
}
