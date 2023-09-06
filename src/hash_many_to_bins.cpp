#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <getopt.h>

#include "../include/hashing.h"

using namespace std;

int main(int argc, char **argv) {
  unsigned int p = 0;
  unsigned int t = 0;

  // Parse command-line options using GNU getopt
  int option;
  while ((option = getopt(argc, argv, "t:p:")) != -1) {
    switch (option) {
    case 'p':
      p = std::atoi(optarg);
      break;
    case 't':
      t = std::atoi(optarg);
      break;
    default:
      cerr << "Bad argument " << endl;
      return 1;
    }
  }

  // Check if the number of partitions is valid
  if (0 == p) {
    std::cerr << "Invalid number of partitions." << std::endl;
    return 1;
  }

  // Create a vector of output file streams for each partition
  std::vector<std::ofstream> binFiles(p);
  for (unsigned int i = 0; i < p; ++i) {
    std::string fileName = "data/partition_" + std::to_string(i) + ".txt";
    binFiles[i].open(fileName);
    if (!binFiles[i]) {
      std::cerr << "Failed to open file: " << fileName << std::endl;
      return 1;
    }
  }

  // Read integer inputs from standard input
  int number;
  while (std::cin >> number) {
    // Compute the hash of the number
    uint64_t hash =
        computeHash(number, 0, 64); // Assuming salt is 0 and k is 64

    // Determine the bin index based on the hash modulo p
    unsigned int binIndex = hash % p;
    if (t) {
      hash %= t;
    }

    // Write the number to the corresponding partition file
    binFiles[binIndex] << number << std::endl;
  }

  // Close all files
  for (unsigned int i = 0; i < p; ++i) {
    binFiles[i].close();
  }

  return 0;
}
