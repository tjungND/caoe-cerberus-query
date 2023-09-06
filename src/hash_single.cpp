#include <cstdlib>
#include <getopt.h>
#include <iostream>

#include "../include/hashing.h"

int main(int argc, char *argv[]) {
  unsigned int t = 0;

  // Parse command-line options using GNU getopt
  int option;
  while ((option = getopt(argc, argv, "t:")) != -1) {
    switch (option) {
    case 't':
      t = std::atoi(optarg);
      break;
    default:
      std::cerr << "Usage: " << argv[0] << " -t <modulus>" << std::endl;
      return 1;
    }
  }

  // Check if modulus t is provided
  if (t == 0) {
    std::cerr << "Missing modulus" << std::endl;
    return 1;
  }

  // Read the number from standard input
  uint64_t number;
  while (std::cin >> number) {
    // Compute the hash of the number
    uint64_t hash =
        computeHash(number, 0, 64); // Assuming salt is 0 and k is 64

    // Output the hash modulo t
    uint64_t hashModP = hash % t;
    std::cout << hashModP << std::endl;
  }

  return 0;
}
