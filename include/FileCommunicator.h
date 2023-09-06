#ifndef FILECOMMUNICATOR_H
#define FILECOMMUNICATOR_H

#include <experimental/filesystem>
#include <fstream>
#include <map>
#include <string>
#include <system_error>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "Communicator.h"
#include "ciphertext-ser.h"
#include <openfhe.h>
// These two may or may not be needed in this file, not sure
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

// needed for serialization
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using lbcrypto::Ciphertext;
using lbcrypto::DCRTPoly;
using namespace std;
namespace fs = std::experimental::filesystem;

class FileCommunicator : public Communicator {
protected:
  std::string _directory;
  std::map<unsigned int, std::ofstream> _output_filestreams;
  std::map<unsigned int, std::ifstream> _input_filestreams;

public:
  FileCommunicator(const unsigned int party_num, const unsigned int num_parties,
                   const std::string &uri)
      : Communicator(party_num, num_parties, uri), _directory(uri) {
    fs::path fsp = uri;
    static const std::string EXTENSION = "comm";

    if (!is_directory(fsp)) {
      std::string error = uri + " is not a valid directory!";
      throw std::runtime_error(error);
    }

    for (unsigned int i = 0; i < this->_num_parties; i++) {
      if (i == this->party_num()) {
        continue;
      }
      std::string output_basename =
          std::to_string(i) + '_' + std::to_string(party_num) + '.' + EXTENSION;
      std::string input_basename =
          std::to_string(party_num) + '_' + std::to_string(i) + '.' + EXTENSION;
      _output_filestreams.emplace(i, std::ofstream(fsp / output_basename));
      _input_filestreams.emplace(i, std::ifstream(fsp / input_basename));
    }
  }

  // Implementation: a ssize_t denotes the number of bytes to
  // send/read, 0 for a finish(), or -1 in case of an error.
  virtual ssize_t send(const unsigned int target_party, const void *buf,
                       const ssize_t len) {
    // Check if buf is valid
    if (buf == nullptr) {
      return -1;
    }
    // Check if output file stream for target_party is open and valid
    if (!_output_filestreams[target_party].is_open() ||
        !_output_filestreams[target_party].good()) {
      return -1;
    }
    if (len <= -1) {
      return len;
    }

    // Write length of data to output file stream
    _output_filestreams[target_party].write((char *)&len, sizeof(len));

    if (len > 0) {
      // Write data to output file stream
      _output_filestreams[target_party].write(static_cast<const char *>(buf),
                                              len);

      // Check if output file stream for target_party is still open and valid
      if (!_output_filestreams[target_party].good()) {
        return -1;
      }
    }

    return len;
  }

  virtual ssize_t read(const unsigned int source_party, void **buf) {

    // Check if buf is valid
    if (buf == nullptr) {
      return -1;
    }

    // Check if output file stream for target_party is open and valid
    if (!_input_filestreams[source_party].is_open() ||
        !_input_filestreams[source_party].good()) {
      return -1;
    }

    ssize_t len;
    _input_filestreams[source_party].read((char *)&len, sizeof(len));

    if (len <= 0) {
      return len;
    } else if (buf == nullptr || *buf != nullptr) {
      return -1;
    } else {
      *buf = malloc(len);
      _input_filestreams[source_party].read((char *)*buf, len);

      // Check if input file stream for source_party is still open and valid
      if (_input_filestreams[source_party].fail()) {
        free(*buf);
        *buf = nullptr;
        return -1;
      }
    }

    return len;
  }

  virtual ssize_t broadcast(const void *buf, const ssize_t len) {
    if (buf == nullptr) {
      return -1;
    }
    ssize_t ret = 0;
    bool fail = false;
#ifdef _OPENMP
#pragma omp parallel for
#endif
    for (unsigned int i = 0; i < _num_parties; i++) {
      if (fail || i == _self) {
        continue;
      }
      ssize_t res = send(i, buf, len);
      if (res != len) {
#ifdef _OPENMP
#pragma omp atomic write
// http://www.physics.ntua.gr/~konstant/HetCluster/intel12.1/compiler_c/main_cls/cref_cls/common/cppref_pragma_omp_atomic.htm
#endif
        fail = true;
      } else {
#ifdef _OPENMP
#pragma omp atomic update
#endif
        ret += res;
      }
    }
    return fail ? -1 : ret;
  }

  virtual ssize_t send(const unsigned int target_party, std::stringstream &ss) {
    // First, get length of the stringstream
    ss.seekg(0, ios::end);
    ssize_t len = ss.tellg();
    // Reset the stream (may not be necessary, but best to be sure)
    ss.seekg(0, ios::beg);

    // Send the length
    if (!_output_filestreams[target_party].good() || len == -1) {
      return -1;
    }
    _output_filestreams[target_party].write((char *)&len, sizeof(len));
    if (len) {
      _output_filestreams[target_party].write(ss.str().c_str(), len);

      // Check if output file stream for target_party is still open and valid
      if (!_output_filestreams[target_party].good()) {
        return -1;
      }
    }

    return len;
  }

  // May be inefficient - does one extra copy, and uses a single large buffer
  // There's a way to reduce one copy, but memory cleanup/ownership is very
  // messy
  virtual ssize_t read(const unsigned int source_party, std::stringstream &ss) {
    // First, get length to read
    if (!_input_filestreams[source_party].good()) {
      return -1;
    }
    ssize_t len;
    _input_filestreams[source_party].read((char *)&len, sizeof(len));
    if (len <= 0 || _input_filestreams[source_party].fail()) {
      return -1;
    }

    if (len == 0) {
      // There is no data to read
      return 0;
    }

    vector<char> buf(len);
    // check if the vector was successfully created
    if (!buf.empty()) {
      _input_filestreams[source_party].read(buf.data(), len);
    }
    if (!_input_filestreams[source_party].good()) {
      return -1;
    }

    if (!ss.good()) {
      // The stringstream is in a bad state
      return -1;
    }

    // actually writing the data to stringstream for read
    ss.write(buf.data(), len);
    return len;
  }

  // Special functions for sending/receiving ciphertexts
  virtual ssize_t send_ciphertext(const unsigned int target_party,
                                  const Ciphertext<DCRTPoly> &ctext) {
    try {
      lbcrypto::Serial::Serialize(ctext, _output_filestreams[target_party],
                                  lbcrypto::SerType::BINARY);
    } catch (const std::exception &e) {
      std::cerr << "Error during serialization: " << e.what() << std::endl;
      return -1;
    }

    return 0;
  }

  virtual ssize_t read_ciphertext(const unsigned int source_party,
                                  Ciphertext<DCRTPoly> &ctext) {
    try {
      lbcrypto::Serial::Deserialize(ctext, _input_filestreams[source_party],
                                    lbcrypto::SerType::BINARY);
    } catch (const std::exception &e) {
      std::cerr << "Error during deserialization: " << e.what() << std::endl;
      return -1;
    }
    return 0;
  }

  virtual ssize_t broadcast_ciphertext(const Ciphertext<DCRTPoly> &ctext) {
    ssize_t ret = 0;
    bool fail = false;
#ifdef _OPENMP
#pragma omp parallel for
#endif
    for (unsigned int i = 0; i < _num_parties; i++) {
      if (fail || i == _self) {
        continue;
      }
      ssize_t res = send_ciphertext(i, ctext);
      if (res == -1) {
#ifdef _OPENMP
#pragma omp atomic                                                             \
    write // http://www.physics.ntua.gr/~konstant/HetCluster/intel12.1/compiler_c/main_cls/cref_cls/common/cppref_pragma_omp_atomic.htm
#endif
        fail = true;
      } else {
#ifdef _OPENMP
#pragma omp atomic update
#endif
        ret += res;
      }
    }
    return fail ? -1 : ret;
  }

  virtual ssize_t broadcast(std::stringstream &ss) {
    // Check if ss is in a bad state
    if (!ss.good()) {
      return -1;
    }
    ssize_t ret = 0;
    bool fail = false;
    ssize_t len = ss.str().length();
#ifdef _OPENMP
#pragma omp parallel for
#endif
    for (unsigned int i = 0; i < _num_parties; i++) {
      if (fail || i == _self) {
        continue;
      }
      ssize_t res = send(i, ss);
      if (res != len) {
#ifdef _OPENMP
#pragma omp atomic write
// http://www.physics.ntua.gr/~konstant/HetCluster/intel12.1/compiler_c/main_cls/cref_cls/common/cppref_pragma_omp_atomic.htm
#endif
        fail = true;
      } else {
#ifdef _OPENMP
#pragma omp atomic update
#endif
        ret += res;
      }
    }
    return fail ? -1 : ret;
  }
};
#endif