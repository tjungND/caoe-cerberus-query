#include "../../include/basic_psi.h"
#include "../../include/powers.h"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>
#include <chrono>


// openFHE
#include "openfhe.h"
using lbcrypto::Ciphertext;
using lbcrypto::DCRTPoly;

using namespace lbcrypto;
using std::vector;
using namespace std::chrono;

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

// data types we will need
using CT = Ciphertext<DCRTPoly>;     // ciphertext
using PT = Plaintext;                // plaintext
using vecCT = std::vector<CT>;       // vector of ciphertexts
using vecPT = std::vector<PT>;       // vector of plaintexts
using vecInt = std::vector<int64_t>; // vector of ints
using vecChar = std::vector<char>;   // vector of characters

using namespace std;


int main() {

  int sender_vals_size = 782;
  int receiver_vals_size = 1;
  int depth = 5;
  int plain_modulus_size = 65537;
  unsigned int source_arr[] = {1, 5, 8, 27, 135};
  unsigned int ps_low_degree = 26;

  //unsigned int source_power_size = 32;  // 1/3 rd of sender_vals_size if no PS


  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetPlaintextModulus(plain_modulus_size);
  parameters.SetMultiplicativeDepth(depth);
  std::cout << "Depth = " << depth << std::endl;
  parameters.SetMaxRelinSkDeg(3);


  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  // enable features that you wish to use
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);

  auto keyPair = cryptoContext->KeyGen();
  PublicKey<DCRTPoly> pk = keyPair.publicKey;
  PrivateKey<DCRTPoly> sk = keyPair.secretKey;
  cryptoContext->EvalMultKeyGen(sk);

  uint64_t plain_modulus = cryptoContext->GetCryptoParameters()
                          ->GetPlaintextModulus();
  std::cout << "Plaintext modulus = " << plain_modulus << std::endl;
  vector<uint64_t> sender_vals;
  
  for (size_t i=1; i<=sender_vals_size; i++){
    sender_vals.push_back(i);
  }


  std::vector<uint64_t> receiver_vals;
  
  for (size_t i=1; i<=receiver_vals_size; i++){
    receiver_vals.push_back(i);
  }


  CT receiverCT;

  std::set<unsigned int> source_powers;
  
  // for (size_t i=0; i<= (int) log2(sender_vals_size); i++){
  //   source_powers.insert(pow(2,i));
  // }

  for( unsigned int i = 0; i < sizeof(source_arr)/sizeof(source_arr[0]); i++ ){
    source_powers.insert(source_arr[i]);
    cout<< source_arr[i] << endl;
  }

  // for (int i = 1; i <= source_power_size; i++) {
  //       source_powers.insert(i);
  //   }

 // time the receiver windowed values function
 steady_clock::time_point start, end;
 long double elapsed_time;

 start = steady_clock::now();
  vector<std::pair<unsigned int, Ciphertext<DCRTPoly>>> query_ciphertexts =
      receiver_windowed_vals(
          receiver_vals, source_powers, cryptoContext,
          pk); // check if it contains the ciphertext with // first element: 6
               // -5 1 and second one 36 25 1
end = steady_clock::now();
elapsed_time = duration_cast<milliseconds>(end - start).count();
std::cout << "Elapsed time for getting windowed values: " << elapsed_time << " ms\n";

std::cout << "Set size: " << query_ciphertexts.size() << std::endl;

  // time for construction sender's matcher polynomial
  start = steady_clock::now();
  vecPT sender_poly_plaintexts = sender_polynomial(sender_vals, cryptoContext);
  end = steady_clock::now();
  elapsed_time = duration_cast<milliseconds>(end - start).count();
  std::cout << "Elapsed time for constructing sender's matcher polynomial: " << elapsed_time << " ms\n";


  PowersDag dag;
  std::set<unsigned int> target_powers;
  for (unsigned int i = 1; i < sender_poly_plaintexts.size(); i++) {
    target_powers.insert(i);
  }
  // time for configuring the powers
  start = steady_clock::now();
  dag.configure(source_powers, target_powers);
  end = steady_clock::now();
  elapsed_time = duration_cast<milliseconds>(end - start).count();
  std::cout << "Elapsed time for configuring the powers: " << elapsed_time << " ms\n";


  // First, read all powers from querier
  // Query must contain a series of (power, ct)
  // For CKKS-based PSI, this will be (1, ct)
  vector<Ciphertext<DCRTPoly>> query_ct_powers;
  query_ct_powers.resize(target_powers.size());

  stringstream ss;
  std::string accumulated_ctxt = "";
  cout << "Target Power size:" << target_powers.size() << "\n";

  int a = 0;
  for (const unsigned int i : source_powers) {

    query_ct_powers[i-1] = query_ciphertexts[a].second;
    lbcrypto::Serial::Serialize(query_ciphertexts[a].second, ss, lbcrypto::SerType::BINARY);
    accumulated_ctxt += ss.str();
    a++;
  }

  cout << "Total Communication per query: " << accumulated_ctxt.size() << " bytes";
  std::cout << "\n";


  // time compute the powers

  start = steady_clock::now();

  compute_all_powers(dag, query_ct_powers, cryptoContext);

 //Ciphertext<DCRTPoly> query_result = eval_sender_poly_dot(
 //      query_ct_powers, sender_poly_plaintexts, cryptoContext);

  Ciphertext<DCRTPoly> query_result = eval_sender_poly_PS(
     query_ct_powers, sender_poly_plaintexts, cryptoContext, ps_low_degree);

  lbcrypto::Serial::Serialize(query_result, ss, lbcrypto::SerType::BINARY);
  std::cout << "Size of result of query: " << ss.str().size() << " bytes";
  std::cout << "\n"; 


  end = steady_clock::now();
  elapsed_time = duration_cast<milliseconds>(end - start).count();
  std::cout << "Elapsed time for checking checking intersection and computing powers: " << elapsed_time << " ms\n";


  //std::cout << "Elapsed time for checking the intersection: " << elapsed_time << " ms\n";




  Plaintext pt11;
  cryptoContext->Decrypt(sk, query_result, &pt11);
  // std::cout<< "plaintext length: " << pt->GetLength() << std::endl;

  vector<int64_t> dec = pt11->GetPackedValue();
  // std::cout << "\n";
  // for (size_t i = 0; i < 10; i++) {
  //   std::cout << "Output from query_result[" << i
  //             << "]:" << dec[i] << std::endl;
  // }

  std::vector<uint64_t> inter_indicies;
  vector<int> res = finite_field_result(query_result, cryptoContext, sk);
  std::cout << "\n";
  for (unsigned int i = 0; i < receiver_vals.size(); i++) {
    //std::cout << "Final Intersection Result[" << i << "]:" << res[i] << std::endl;
    if (res[i]){
      inter_indicies.push_back(i);
    }
  }
  std::cout << "\n";

  std::cout << "Intersection indices = {";
 for (auto it = inter_indicies.begin(); it != inter_indicies.end(); ++it) {
   std::cout << *it;
   if (std::next(it) != inter_indicies.end()) {
     std::cout << ", ";
   }
 }
 std::cout << "}\n";


  //    Plaintext pt;
  // cryptoContext->Decrypt(sk, query_ciphertexts[i-1].second, &pt);
  // const std::vector<int> &vec_result11 = pt->GetPackedValue();

  // std::cout << "\n";
  // for (size_t i = 0; i < 10; i++) {
  //   std::cout << "Output inside the serialization[" << i
  //             << "]:" << vec_result11[i] << std::endl;
  // }


  return 0;
}
