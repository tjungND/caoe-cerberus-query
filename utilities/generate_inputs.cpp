#include <fstream>
#include <getopt.h>
#include <iostream>
#include <random>
#include <set>

using namespace std;

// Generate a random 32-bit number
uint32_t generate_random_32() {
  static random_device rd;
  static mt19937 gen(rd());
  uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
  return dis(gen);
}

// Generate a random 64-bit number
uint64_t generate_random_64() {
  static random_device rd;
  static mt19937_64 gen(rd());
  uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
  return dis(gen);
}

int main(int argc, char **argv) {
  // Default values for command-line arguments
  bool bit32 = true;
  int sender_size = 100;
  int receiver_size = 10;
  double present_fraction = 0.2;
  bool deterministic = true;

  string sender_fname = "data/sender.txt";
  string receiver_fname = "data/receiver.txt";

  // Parse command-line arguments
  int c;
  while ((c = getopt(argc, argv, "bs:r:p:na:c:")) != -1) {
    switch (c) {
    case 'b': {
      bit32 = false;
      break;
    }
    case 's': {
      sender_size = atoi(optarg);
      break;
    }
    case 'r': {
      receiver_size = atoi(optarg);
      break;
    }
    case 'p': {
      present_fraction = atof(optarg);
      break;
    }
    case 'n': {
      deterministic = false;
      break;
    }
    //a is receiver, c is sender
  case 'a':{
    receiver_fname = optarg;
    break;
  }
case 'c':{
    sender_fname = optarg;
    break;
  }
    default:
      cout << "Invalid argument: " << c << endl;
      return 1;
    }
  }

  // Open output files
  ofstream sender_file(sender_fname);
  ofstream receiver_file(receiver_fname);

  uint32_t input32 = 2;
  uint64_t input64 = 2;
  int present_num_size = static_cast<int>(present_fraction * receiver_size);

  set<uint32_t> uint32_t_set;
  set<uint64_t> uint64_t_set;

  // Generate receiver's set
  if (deterministic) {
    for (int i = 0; i < receiver_size; i++) {
      if (bit32) {
        receiver_file << input32 << endl;
        input32++;
      } else {
        receiver_file << input64 << endl;
        input64++;
      }
    }
  }

  if (!deterministic) {
    for (int i = 0; i < receiver_size; i++) {
      if (bit32) {
        uint32_t_set.insert(generate_random_32());
      } else {
        uint64_t_set.insert(generate_random_64());
      }
    }
  }

  set<uint32_t>::iterator itr32;
  set<uint64_t>::iterator itr64;

  if (bit32) {
    for (itr32 = uint32_t_set.begin(); itr32 != uint32_t_set.end(); itr32++) {
      receiver_file << (*itr32) << endl;
    }
  } else {
    for (itr64 = uint64_t_set.begin(); itr64 != uint64_t_set.end(); itr64++) {
      receiver_file << (*itr64) << endl;
    }
  }

  // receiver's operations done

  // reset the inputs for sender
  input32 = 2;
  input64 = 2;

  // generate the sender set
  if (deterministic) {
    for (int i = 0; i < present_num_size; i++) {
      if (bit32) {
        sender_file << input32 << endl;
        input32++;
      } else {
        sender_file << input64 << endl;
        input64++;
      }
    }

    input32 = receiver_size+2;
    input64 = receiver_size+2;

    for (auto i = present_num_size; i < sender_size+2; i++) {
      if (bit32) {
        sender_file << input32 << endl;
        input32++;
      } else {
        sender_file << input64 << endl;
        input64++;
      }
    }
  }

  // resetting the sets
  uint32_t_set.clear();
  uint64_t_set.clear();

  if (!deterministic) {
    for (int i = 0; i < sender_size; i++) {
      if (bit32) {
        uint32_t_set.insert(generate_random_32());
      } else {
        uint64_t_set.insert(generate_random_64());
      }
    }
  }

  // populating the sender file
  if (bit32) {
    for (itr32 = uint32_t_set.begin(); itr32 != uint32_t_set.end(); itr32++) {
      sender_file << (*itr32) << endl;
    }
  } else {
    for (itr64 = uint64_t_set.begin(); itr64 != uint64_t_set.end(); itr64++) {
      sender_file << (*itr64) << endl;
    }
  }

  return 0;
}
