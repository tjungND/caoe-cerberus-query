// sudo apt-get -y install libjsonrpccpp-dev
// sudo apt-get install libjsonrpccpp-dev libjsonrpccpp-tools (https://github.com/cinemast/libjson-rpc-cpp)
// g++ read_params.cpp -ljsoncpp -o read_params

#include <iostream>
#include <jsoncpp/json/json.h>
#include <fstream>
#include <string>
#include <cassert>

using namespace std;

int main() {

    string fname;
    cin >> fname;

    ifstream file(fname);
    assert(file.good());
    Json::Value actualJson;
    Json::Reader reader;

    reader.parse(file, actualJson);

    // Print max_items_per_bin
    int max_items_per_bin = actualJson["table_params"]["max_items_per_bin"].asInt();
    std::cout << max_items_per_bin << std::endl;

    // Print ps_low_degree
    int ps_low_degree = actualJson["query_params"]["ps_low_degree"].asInt();
    std::cout << ps_low_degree << std::endl;

    // Print query_powers
    string pow_str;
    for (const auto& power : actualJson["query_params"]["query_powers"]) {
        pow_str += "-s " + to_string(power.asInt()) + " ";
    }
    std::cout << pow_str << std::endl;

    return 0;
}
