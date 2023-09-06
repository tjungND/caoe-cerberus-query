#!/bin/bash

# Compile the C++ program
g++ -o read_params read_params.cpp -ljsoncpp

# Run the program and capture the output
output=$(./read_params)

# Store the output values in separate variables
#  sed command extracts the values based on line numbers
#  sed -n 'Np' is used to print the specific line number N from the input
# '1p' for the first line, '2p' for the second line, and '3p' for the third line

MAX_ITEMS_PER_BIN=$(echo "$output" | sed -n '1p')
PS_LOW_DEGREE=$(echo "$output" | sed -n '2p')
QUERY_POWERS=$(echo "$output" | sed -n '3p')

# captured values
echo $MAX_ITEMS_PER_BIN
echo $PS_LOW_DEGREE
echo $QUERY_POWERS
