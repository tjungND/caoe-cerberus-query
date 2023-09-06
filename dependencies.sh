#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

set -e
set -x

sudo apt update
sudo apt install -y parallel libjsonrpccpp-dev libjsonrpccpp-tools g++ openssl openssl-dev libomp-dev git build-essential cmake make autoconf
touch ~/.parallel/will-cite #Include this to suppress annoying GNU Parallel message

git clone https://github.com/openfheorg/openfhe-development.git
cd openfhe-development
mkdir build && cd build
cmake .. -DBUILD_STATIC=ON -DNATIVE_SIZE=128
NUM_CPUS=$(nproc --all)
sudo make install -j $NUM_CPUS
