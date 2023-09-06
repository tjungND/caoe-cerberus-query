
#include <cassert>
#include <getopt.h>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "../include/FileCommunicator.h"
#include "../include/basic_psi.h"
#include "../include/common.h"
#include "../include/new_psi.h"

using namespace lbcrypto;
using namespace std;

int main(int argc, char **argv) {

  std::set<unsigned int> source_powers;
  source_powers.insert(1);
  string pk_file, context_file, sk_file, communicator_uri;
  unsigned int chebyshev_approx_degree = 0;
  unsigned int num_senders = 1;
  bool encrypt_only = false;
  bool fresh_input =
      true; // Determines whether to read plaintext input from stdin (true) or
            // read and immediately send inputs from stdin (false)
  Method method = FINITE_FIELD;
  unsigned int ps_bound = 0;

  int c;
  while ((c = getopt(argc, argv, "p:k:c:s:u:a:n:eib:l:")) != -1) {
    switch (c) {
    case 'l': {
      ps_bound = atoi(optarg);
      break;
    }
    case 'e': {
      encrypt_only = true;
      break;
    }
    case 'b': {
      method = APPROXIMATE;
      break;
    }
    case 'p': {
      unsigned int pow = atoi(optarg);
      if (pow) {
        source_powers.insert(pow);
      } else {
        cerr << "Error: invalid source power: " << optarg << endl;
        return 1;
      }
      break;
    }
    case 'k': {
      pk_file = optarg;
      break;
    }
    case 'c': {
      context_file = optarg;
      break;
    }
    case 's': {
      sk_file = optarg;
      break;
    }
    case 'u': {
      communicator_uri = optarg;
      break;
    }
    case 'a': {
      chebyshev_approx_degree = atoi(optarg);
      if (chebyshev_approx_degree <= 1) {
        cerr << "Error: Chebyshev approximation degree is too low: " << optarg
             << endl;
        return 1;
      }
      break;
    }
    case 'n': {
      num_senders = atoi(optarg);
      if (!num_senders) {
        cerr << "Invalid number of senders: " << optarg << endl;
        return 1;
      }
      break;
    }
    default:
      std::cout << "Invalid argument: " << c << std::endl;
      return 1;
    }
  }

  // Validate inputs
  assert(sk_file != "");
  assert(pk_file != "");
  assert(context_file != "");
  assert(communicator_uri != "");
  assert(chebyshev_approx_degree > 1);
  assert(num_senders >= 1);

  if (ps_bound) {
    // TODO decide if/how to override argued powers
  }

  // Deserialize - a lot of this code is shared with sender.cpp
  //  CryptoContext
  CryptoContext<DCRTPoly> cryptoContext;
  cryptoContext->ClearEvalMultKeys();
  cryptoContext->ClearEvalAutomorphismKeys();
  lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
  if (!Serial::DeserializeFromFile(context_file, cryptoContext,
                                   SerType::BINARY)) {
    std::cerr << "Cannot read serialized data from: " << context_file
              << std::endl;
    return 1;
  }
  // Public key
  PublicKey<DCRTPoly> pubKey;
  if (!Serial::DeserializeFromFile(pk_file, pubKey, SerType::BINARY)) {
    std::cerr << "Cannot read serialized data from: " << pk_file << std::endl;
    return 1;
  }

  vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>> query_ciphertexts;
  if (fresh_input) {
    uint64_t val;
    vector<uint64_t> values;
    values.reserve(USER_INPUT_GUESS);
    while (std::cin >> val) {
      values.push_back(val);
    }
    // Now encrypt these
    // vector<std::pair<Ciphertext<DCRTPoly>, unsigned int>> query_powers;
    if (method == FINITE_FIELD) {
      query_ciphertexts =
          receiver_windowed_vals(values, source_powers, cryptoContext, pubKey);
    } else {
      query_ciphertexts.resize(1);
      query_ciphertexts[0].first = 1;
      query_ciphertexts[0].second =
          receiver_encrypt(values, cryptoContext, pubKey);
    }
  } else {
    // Read ciphertexts in from input
    query_ciphertexts.resize(source_powers.size());
    unsigned int idx = 0;
    for (const unsigned int i : source_powers) {
      query_ciphertexts[idx].first = i;
      Serial::Deserialize(query_ciphertexts[idx].second, std::cin,
                          lbcrypto::SerType::BINARY);

      idx++;
    }
  }

  if (encrypt_only && !fresh_input) {
    // Write ciphertext(s) out in order
    for (const auto &p : query_ciphertexts) {
      Serial::Serialize(p.second, std::cout, lbcrypto::SerType::BINARY);
    }
  }

  // Querier is party 0
  Communicator *comm =
      new FileCommunicator(0, num_senders + 1, communicator_uri);

  // Send ciphertext(s) to sender(s) and get a response
  for (unsigned int i = 0; i < query_ciphertexts.size(); i++) {
    comm->broadcast_ciphertext(query_ciphertexts[i].second);
  }

  // Secret key - could read this earlier, but not much of a need
  PrivateKey<DCRTPoly> secKey;
  if (!Serial::DeserializeFromFile(sk_file, secKey, SerType::BINARY)) {
    std::cerr << "Cannot read serialized data from: " << sk_file << std::endl;
    return 1;
  }

  // Get a response - currently hardcoded for only 1 sender.
  // TODO reconfigure for multiparty
  Ciphertext<DCRTPoly> result;
  comm->read_ciphertext(1, result);
  // Interpret and print result
  vector<int> results_plain;
  if (method == FINITE_FIELD) {
    results_plain = finite_field_result(result, cryptoContext, secKey);
  } else {
    results_plain = in_intersection(result, K_DEFAULT, cryptoContext, secKey);
  }
  // Print results
  for (const int i : results_plain) {
    std::cout << i << '\n';
  }

  delete comm;
  comm = nullptr;

  return 0;
}
