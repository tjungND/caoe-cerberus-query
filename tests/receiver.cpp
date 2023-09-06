#include "../include/Communicator.h"
#include "../include/FileCommunicator.h"
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <string>

// g++ -std=c++17 -Wall -Werror -o receiver receiver.cpp -DOPENFHE_VERSION=1.0.3 -Wno-parentheses -DMATHBACKEND=4 -fopenmp  -Wl,-rpath,/usr/local/lib/ /usr/local/lib/libOPENFHEcore.so /usr/local/lib/libOPENFHEpke.so -fopenmp /usr/local/lib/libOPENFHEpke_static.a /usr/local/lib/libOPENFHEcore_static.a
//-fopenmp -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/ -lstdc++fs

int main(int argc, char *argv[]) {

  // don't modify these numbers for now - modification will be made later for multiple receivers
  int party_num = 1;
  int num_parties = 2;
  std::string uri = "./data";

  // Parse command-line arguments
  int c;
  while ((c = getopt(argc, argv, "p:n:l:")) != -1) {
    switch (c) {
    case 'p': {
      party_num = atoi(optarg);
      break;
    }
    case 'n': {
      num_parties = atoi(optarg);
      break;
    }
    case 'l': {
      uri = optarg;
      break;
    }
    default:
      std::cout << "Invalid argument: " << c << std::endl;
      return 1;
    }
  }

  FileCommunicator comm(party_num, num_parties, uri);

  while (true) {

    //void *buf = nullptr;
    //ssize_t bytes_read = comm.read(0, &buf);
    std::stringstream ss;
    ssize_t bytes_read = comm.read(0, ss);

    if (bytes_read == 0) {
      std::cout << "Received message has len " << bytes_read << std::endl;
    } else if (bytes_read == -1) {
      std::cerr << "Done." << std::endl;
      return 1;
    } else {
      //std::string message(static_cast<char *>(buf), bytes_read);
      std::cout << ss.str() << std::endl;
    }

    //delete[] static_cast<char *>(buf);
  }

  return 0;
}
