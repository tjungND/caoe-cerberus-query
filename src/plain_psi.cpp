#include <algorithm> // std::set_intersection, std::sort
#include <chrono>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <set>
#include <sstream>
#include <time.h>
#include <unordered_set>
#include <vector>

using namespace std::chrono;
using measure_typ = std::chrono::nanoseconds;

int main(int argc, char **argv) {
  // Default values for command-line arguments
  std::string sender_file_name = "";
  std::string receiver_file_name = "";
  steady_clock::time_point start, end;

  // Parse command-line arguments
  int c;
  while ((c = getopt(argc, argv, "s:r:")) != -1) {
    switch (c) {
    case 's': {
      sender_file_name = optarg;
      break;
    }
    case 'r': {
      receiver_file_name = optarg;
      break;
    }
    default:
      std::cout << "Invalid argument: " << c << std::endl;
      return 1;
    }
  }

  // Open input files
  std::ifstream sender_file(sender_file_name);
  std::ifstream receiver_file(receiver_file_name);
  // std::ofstream intersection_results("intersection_results.txt");
  std::ofstream timing("timing.csv");

  // Check if input files are open
  if (!sender_file.is_open() || !receiver_file.is_open()) {
    std::cout << "Failed to open input files." << std::endl;
    return 1;
  }

  std::vector<uint64_t> sender_data;
  std::vector<uint64_t> receiver_data;

  sender_data.reserve(1024);
  receiver_data.reserve(1024);

  // Read the data from the files and buffer the writes to the vector
  uint64_t num;
  while (sender_file >> num) {
    sender_data.push_back(num);
  }
  while (receiver_file >> num) {
    receiver_data.push_back(num);
  }

  sender_file.close();
  receiver_file.close();

  // pre-processing for intersection
  std::sort(sender_data.begin(), sender_data.end());
  std::sort(receiver_data.begin(), receiver_data.end());

  std::vector<uint64_t> intersection;
  intersection.reserve(1024);

  start = steady_clock::now();

  // Check for intersection
  std::set_intersection(sender_data.begin(), sender_data.end(),
                        receiver_data.begin(), receiver_data.end(),
                        back_inserter(intersection));

  end = steady_clock::now();
  long double d = duration_cast<measure_typ>(end - start).count();

  if (!intersection.empty()) {
    for (std::uint64_t n : intersection) {
      // Was previously writing to file
      std::cout << n << std::endl;
    }
  }
  // intersection_results.close();

  try {
    timing << "intersection";
    timing << ",";
    timing << d;
    timing << "\n";
  } catch (const std::exception &ex) {
    std::cout << "Exception was thrown: " << ex.what() << std::endl;
  }
  timing.close();

  return 0;
}
