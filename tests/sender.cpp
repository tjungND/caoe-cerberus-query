#include "../include/Communicator.h"
#include "../include/FileCommunicator.h"
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <string>

// g++ -Wall -Werror -std=c++17 -o sender sender.cpp -DOPENFHE_VERSION=1.0.3 -Wno-parentheses -DMATHBACKEND=4 -fopenmp  -Wl,-rpath,/usr/local/lib/ /usr/local/lib/libOPENFHEcore.so /usr/local/lib/libOPENFHEpke.so
// -fopenmp /usr/local/lib/libOPENFHEpke_static.a /usr/local/lib/libOPENFHEcore_static.a -fopenmp -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/ -lstdc++fs

int main(int argc, char *argv[]) {
  // don't modify these numbers for now
  int party_num = 0;
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

  std::string message;
  while (true) {

    std::getline(std::cin, message);
    if (message.empty()) {
      comm.finish();  // TO-DO
      std::cout << "Sender is done." << std::endl;
      break;
    }
    std::stringstream ss(message);
    //ssize_t bytes_sent = comm.send(1, message.c_str(), message.length());
    //ssize_t bytes_sent = comm.broadcast(message.c_str(), message.length());
    //ssize_t bytes_sent = comm.send(1, ss);
    ssize_t bytes_sent = comm.broadcast(ss);
    if (bytes_sent == -1) {
      std::cerr << "Error sending message." << std::endl;
      return -1;
    }
  }

  return 0;
}
