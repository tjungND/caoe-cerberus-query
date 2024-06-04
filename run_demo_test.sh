#!/bin/bash

: "${INTERSECTION:=0}"
: "${NUM_PARTIES:=32}" 
: "${NUM_KEY_SHARES:=4}"
: "${SENDER_BITS=10}"


: "${DEPTH=30}" #3 + log_2(Parties) for BFV
: "${ITER=1}"
: "${TYPE:=CKKS}"

# Create or overwrite the result.txt file
> ckks_16parties_7bits.txt

{ time NUM_KEY_SHARES=$NUM_KEY_SHARES INTERSECTION=$INTERSECTION SENDER_BITS=$SENDER_BITS DEPTH=$DEPTH NUM_PARTIES=$NUM_PARTIES TYPE=$TYPE ./demo_test.sh; } 2>&1 | tee -a ckks_16parties_7bits.txt

