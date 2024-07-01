#!/bin/bash

: "${INTERSECTION:=1}"
: "${NUM_PARTIES:=32}" 
: "${NUM_KEY_SHARES:=4}"
: "${SENDER_BITS=10}"


: "${DEPTH=8}" #3 + log_2(Parties) for BFV
: "${ITER=1}"
: "${TYPE:=BFV}"

# Create or overwrite the result.txt file
> bfv_32parties_30bits.txt

{ time NUM_KEY_SHARES=$NUM_KEY_SHARES INTERSECTION=$INTERSECTION SENDER_BITS=$SENDER_BITS DEPTH=$DEPTH NUM_PARTIES=$NUM_PARTIES TYPE=$TYPE ./demo_test.sh; } 2>&1 | tee -a bfv_32parties_30bits.txt
