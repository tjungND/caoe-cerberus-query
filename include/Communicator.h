#ifndef COMMUNICATOR_H
#define COMMUNICATOR_H

#include <sstream>
#include <string>

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

class Communicator {
protected:
  unsigned int _self;
  unsigned int _num_parties;
  // I also thought about keeping track of the parties that have sent a finished
  // signal, but that's probably better done at the application level.
public:
  Communicator(const unsigned int party_num, const unsigned int num_parties,
               const std::string &uri)
      : _self(party_num), _num_parties(num_parties) {}

  // Implementation: first send a ssize_t denoting the number of bytes to
  // send/read, or -1 to finish.
  virtual ssize_t send(const unsigned int target_party, const void *buf,
                       const ssize_t len) = 0;
  virtual ssize_t read(const unsigned int source_party, void **buf) = 0;
  virtual ssize_t broadcast(const void *buf, const ssize_t len) = 0;

  virtual ssize_t send_ciphertext(const unsigned int party_num,
                                  const Ciphertext<DCRTPoly> &ctext) = 0;
  virtual ssize_t read_ciphertext(const unsigned int party_num,
                                  Ciphertext<DCRTPoly> &ctext) = 0;
  virtual ssize_t broadcast_ciphertext(const Ciphertext<DCRTPoly> &ctext) = 0;

  virtual ssize_t send(const unsigned int party_num, std::stringstream &ss) = 0;
  virtual ssize_t read(const unsigned int source_party,
                       std::stringstream &ss) = 0;
  virtual ssize_t broadcast(std::stringstream &ss) = 0;

  inline unsigned int party_num() const { return _self; }
  inline unsigned int num_parties() const { return _num_parties; }

  virtual ~Communicator() = default;
};

#endif