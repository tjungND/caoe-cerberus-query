#!/bin/bash

#Turn this on for the "executive summary" only
: "${EXECUTIVE:=1}"
#Variables defining which computations to do
: "${SETUP:=1}"
: "${PRECOMPUTE:=1}"
: "${ONLINE:=1}"
: "${DO_HASHING:=0}"
: "${PARALLEL:=0}"
: "${ONE_SITE:=1}"
: "${INTERSECTION:=0}"
: "${TYPE:=CKKS}"
#Parameters for multiparty functionality
: "${NUM_PARTIES:=8}"
: "${NUM_KEY_SHARES:=2}"
: "${SENDER_BITS:=8}"
# SENDER_BITS has to be one of these: 8, 10, 13, 15, 20

BASH_FLAGS=""
if [ $EXECUTIVE -eq "0" ]; then
  echo $EXECUTIVE
  set -x
  set -e
  BASH_FLAGS="-x -e"
fi  


if [ $EXECUTIVE -eq "1" ]; then
  echo "Note: script is in demo mode, output is minimal"
fi
if [ $ONE_SITE -eq "1" ]; then
  echo "Note: this demo is only running one site online"
fi

#Create directories and make executables
mkdir -p data bin keys
if [ $SETUP -eq "1" ]; then
  rm -rf ./data/*
  if [ $EXECUTIVE -eq "1" ]; then
    echo "Building programs..."
  fi  
  make drivers hashes plain_psi utilities/generate_inputs utilities/read_params zero_ct -j 8 > /dev/null
  if [ $EXECUTIVE -eq "1" ]; then
    echo -e "\tFinished building programs"
  fi
fi  


NUM_SENDER_INPUTS=$(echo "2^$SENDER_BITS" | bc) #Implicit: inputs per region; this will be divided among parties and partitions
DEPTH=23
#Input parameters here
#NUM_SENDER_INPUTS=8192 #Implicit: inputs per region; this will be divided among parties and partitions
NUM_PARTITIONS=1

FAKE_EMAIL_FILE=data/fake_emails.txt
if [ $SETUP -eq "1" ]; then
  #Generate some email addresses
  NUM_EMAILS=$(( $NUM_SENDER_INPUTS+10 ))
  echo "Generating $NUM_EMAILS fake emails..."
  python3 utilities/gen_emails.py $FAKE_EMAIL_FILE $NUM_EMAILS > /dev/null
  echo -e "\tFinished generating fake emails."
fi

JSON_PARAMS_DIR=./utilities/apsi_params
mapfile -t JSON_FILES < <(find "$JSON_PARAMS_DIR" -type f -name "*.json")
JSON_FILE_IDX=1
JSON_BASENAME="${JSON_FILES[JSON_FILE_IDX]}"
#JSON_FILE="$JSON_BASENAME/${JSON_BASENAME#"$JSON_PARAMS_DIR"/}"
JSON_FILE=$JSON_BASENAME
if [ $EXECUTIVE -eq "0" ]; then
  echo "Available JSON parameter files: ${JSON_FILES[@]}"
  echo "Using APSI params from $JSON_FILE"
fi  

NUM_INPUTS_PER_PARTITION=$(( $NUM_SENDER_INPUTS / $NUM_PARTITIONS ))



#Parameters for different regions
NUM_REGIONS=1
REGION=0
for ((i = 0 ; i < $NUM_REGIONS ; i++)); do
  mkdir -p ./data/region_${i}
done
#NUM_INPUTS_PER_FILE=$(( $NUM_INPUTS_PER_PARTITION / $NUM_REGIONS ))
SITE_INPUTS_PER_REGION=$(($NUM_SENDER_INPUTS / $NUM_PARTIES))



#Compile JSON reading program
JSON_READER=bin/read_params
JSON_OUTPUT=$(./$JSON_READER <<< $(echo $JSON_FILE))
MAX_ITEMS_PER_BIN=$(echo "$JSON_OUTPUT" | sed -n '1p')
PS_LOW_DEGREE=$(echo "$JSON_OUTPUT" | sed -n '2p')
QUERY_POWERS=$(echo "$JSON_OUTPUT" | sed -n '3p')

RECEIVER_INPUT=1 #Change this line to get an intersection - TODO automate testing intersection/non-intersection cases
GEN=bin/generate_inputs
#Generate some inputs
PLAIN_INPUT_DIR=data/
START_POINT=2
if [ $PRECOMPUTE -eq "1" ]; then
  for ((i = 0 ; i < $NUM_REGIONS ; i++)); do
    #Dummy reciever inputs at this point
    #Probably can rewrite input generation to only get a sender dataset
    #Old method below:
    #$GEN -b -s $NUM_SENDER_INPUTS -r 1 -a /dev/null -c ./data/region_${REGION}/sender.txt #-p to control the proportion of intersecting elements
    for ((k=0; k < $NUM_PARTIES; k++)); do
      #Write inputs to a file
      python3 utilities/print_num.py $START_POINT $SITE_INPUTS_PER_REGION > data/region_${i}/raw_input_party_${k}.txt
      START_POINT=$(tail -n 1 data/region_${i}/raw_input_party_${k}.txt)
      ((START_POINT++))
    done
  done
fi  
if [ $INTERSECTION -eq "1" ]; then
  RECEIVER_INPUT=2
fi


#God bless ChatGPT
EMAIL=$(sed -n "${RECEIVER_INPUT}p" "$FAKE_EMAIL_FILE" | awk '{print $2}')


#echo "Starting value: $START_POINT"

REGION_DIR=data/region_${REGION}/

#This line changes the receiver query
echo $RECEIVER_INPUT > data/receiver.txt

#First, run plain PSI
#Compile the program
#TODO temporarily removed - readd with multiple sites
#PLAIN=bin/plain_psi
#PLAIN_RESULT=$($PLAIN -s $PLAIN_INPUT_FILE -r data/receiver.txt)
#echo Plain result is $PLAIN_RESULT

if [ "$TYPE" = "BFV" ]; then
  DEPTH=8
fi

#Parameter files
PRIVATE_KEY_BASE=data/privatekey_
PRIVATE_KEY_EXT=.bin
KEY_FILE_ARGS_NO_PRIVKEY="-c data/context.bin -p data/publickey.bin -e data/evalkeys.bin"

if [ $PRECOMPUTE -eq "1" ]; then
  if [ $EXECUTIVE -eq "0" ]; then
    echo "Generating FHE parameters/keys..."
  fi
  #Run key generation program to get APSI/SPSI keys/params
  PLAINTEXT_SPACE_BITS=30
  KEYGEN=bin/gen_params
  KEYGEN_OUTPUT=$($KEYGEN -t $TYPE -s $PLAINTEXT_SPACE_BITS -d $DEPTH -f data -p $NUM_KEY_SHARES)
  PLAIN_MODULUS=$(echo "$KEYGEN_OUTPUT" | sed -n '1p')
  CONTEXT_FILE=$(echo "$KEYGEN_OUTPUT" | sed -n '2p')
  PUBLIC_KEY_FILE=$(echo "$KEYGEN_OUTPUT" | sed -n '3p')
  #PRIVATE_KEY_FILE=$(echo "$KEYGEN_OUTPUT" | sed -n '4p')
  PRIVATE_KEY_BASE=data/privatekey_
  PRIVATE_KEY_EXT=.bin
  EVK_FILE=$(echo "$KEYGEN_OUTPUT" | sed -n '5p')
  KEY_FILE_ARGS="-c $CONTEXT_FILE -p $PUBLIC_KEY_FILE -r $PRIVATE_KEY_FILE -e $EVK_FILE"
  KEY_FILE_ARGS_NO_PRIVKEY="-c $CONTEXT_FILE -p $PUBLIC_KEY_FILE -e $EVK_FILE"
  if [ $EXECUTIVE -eq "0" ]; then
    echo "Finished generating FHE parameters/keys"
  fi
fi

#Override the plaintext modulus bits for CKKS
if [ "$TYPE" = "CKKS" ]; then
  PLAIN_MODULUS=10000 #TODO hardcoding is bad
  if [[ !$EXECUTIVE ]]; then
    echo "Running SPSI Protocol with $NUM_PARTIES sites! (Selected region $REGION, data split to $NUM_PARTITIONS partitions)"
  fi
fi



if [ $ONLINE -eq "1" ]; then
  #First, hash receiver input
  HASH_INPUT=bin/hash_single
  if [[ $DO_HASHING -eq "0" ]] ; then
    RECEIVER_INTEGER_VAL=$(cat data/receiver.txt)
  else
    RECEIVER_INTEGER_VAL=$($HASH_INPUT -t $PLAIN_MODULUS < data/receiver.txt)	
  fi
  echo "Receiver query: $EMAIL (global ID number $RECEIVER_INTEGER_VAL)"
  echo "Senders' total set size: $NUM_SENDER_INPUTS"

  #Second, hash sender input to partitions
  #Program name is a misnomer, these will be hashed to partitions
  HASH_DATABASE=bin/hash_many_to_bins

  #Outputs will be in data/partition_i.bin
  #First, hash to partitions...
  for ((j=0; j < $NUM_PARTIES; j++)); do
    if [ $NUM_PARTITIONS -ne "1" ]; then
      $HASH_DATABASE -t $PLAIN_MODULUS -p $NUM_PARTITIONS < data/region_${REGION}/raw_input_party_${j}.txt
    else
      cp data/region_${REGION}/raw_input_party_${j}.txt data/partition_0.txt
    fi  
    #...then hash within a partition to the plaintext space
    for (( i=0; i<$NUM_PARTITIONS; i++ ))
    do
      rm -f data/region_${REGION}/hashed_partition_${i}_${j}.txt
      if [ $DO_HASHING -eq "1" ] ; then
        $HASH_INPUT -t $PLAIN_MODULUS < data/partition_${i}.txt >> data/region_${REGION}/hashed_partition_${i}_${j}.txt
      else
        cat data/partition_${i}.txt >> data/region_${REGION}/hashed_partition_${i}_${j}.txt
      fi  
    done  
  done
fi  

#Run receiver program to generate query (shunt to file)
#Dummy -s 1 added
if [ $ONLINE -eq 1 ]; then
  if [ $EXECUTIVE -eq "1" ]; then
    echo "Running client query encryption..."
  fi
  bin/receiver -t $TYPE $KEY_FILE_ARGS_NO_PRIVKEY -s 1 $QUERY_POWERS <<< "$RECEIVER_INTEGER_VAL" > data/query.ctext
  if [ $EXECUTIVE -eq "1" ]; then
    echo -e "\t Finished running client query encryption"
  fi
fi  

#Run sender program to do computation (shunt result to file)
#If using APSI, run 1 partition at a time
#If using SPSI, then run with 1 partition, aggregating all into a single ciphertext
# Number of instances to run in parallel
SENDER_CMD_FILE=data/sender_commands.sh
SENDER_ENCRYPT_CMD_FILE=data/sender_encrypt_commands.sh
rm -rf $SENDER_CMD_FILE $SENDER_ENCRYPT_CMD_FILE
touch $SENDER_CMD_FILE $SENDER_ENCRYPT_CMD_FILE
for ((j=0; j<NUM_PARTIES; j++)); do
  {
  if [ "$TYPE" = "BFV" ]; then
    k=$NUM_PARTITIONS
    # Define the command to run
    command_online="bin/sender -t $TYPE $KEY_FILE_ARGS_NO_PRIVKEY $QUERY_POWERS -l $PS_LOW_DEGREE"
    #Attempts at running in parallel
    # Generate a list of input files
    #files=$(seq -f "-m data/hashed_partition_%g.txt" 0 $((k-1)))
    # Run the command in parallel
    #Shunt error to /dev/null to get rid of the citation notice
    #echo "$files" | parallel --ungroup --verbose 2> /dev/null --citation <<< "will cite" -P $k $command {} "< query.ctext > result_{}.ctext"
    #echo "$files" | xargs -I {} -P $k $command {} < query.ctext > result_${k}.ctext
    
    #Current lazy workaround: one at a time
    for ((i=0; i<NUM_PARTITIONS; i++)); do
      # Run the program and capture the output
      #Input file should be doubly indexed by party and partition
      SENDER_POLY_FILE=data/region_${REGION}/sender_${i}_${j}.ctext #Slight misnomer, as this file could contain plaintexts in the APSI case
      if [ $PRECOMPUTE -eq "1" ]; then
        if [ $j -eq "0" ] || [ $ONE_SITE -eq "0" ]; then
          echo "bin/sender_encrypt -t $TYPE $KEY_FILE_ARGS_NO_PRIVKEY $QUERY_POWERS < data/region_${REGION}/hashed_partition_${i}_${j}.txt > $SENDER_POLY_FILE" >> $SENDER_ENCRYPT_CMD_FILE
        fi  
      fi
      if [ $ONLINE -eq "1" ]; then
        if [ $j -eq "0" ] || [ $ONE_SITE -eq "0" ]; then
          echo "$command_online -m $SENDER_POLY_FILE < data/query.ctext > data/result_${i}_${j}.ctext" >> $SENDER_CMD_FILE
        fi  
      fi  
    done
  else
    SENDER_PLAIN_FILE=data/region_${REGION}/sender_plain_inputs_singlepartition_${j}.txt
    SENDER_CTEXT_FILE=data/region_${REGION}/sender_ctext_${j}.ctext
    if [ $PRECOMPUTE -eq "1" ]; then
      cat data/region_${REGION}/hashed_partition_*_${j}.txt > $SENDER_PLAIN_FILE #Combine things back into 1 "partition" for SPSI
      #Precompute sender encryption
      if [ $j -eq "0" ] || [ $ONE_SITE -eq "0" ]; then
        echo "bin/sender_encrypt -t $TYPE $KEY_FILE_ARGS_NO_PRIVKEY $QUERY_POWERS < $SENDER_PLAIN_FILE > $SENDER_CTEXT_FILE" >> $SENDER_ENCRYPT_CMD_FILE
      fi
    fi
    if [ $ONLINE -eq "1" ]; then  
      if [ $j -eq "0" ] || [ $ONE_SITE -eq "0" ]; then
        echo "bin/sender -t $TYPE $KEY_FILE_ARGS_NO_PRIVKEY -s 1 -b $SENDER_BITS -l $PS_LOW_DEGREE -m $SENDER_CTEXT_FILE < data/query.ctext > data/result_0_${j}.ctext -r data/privatekey_0.bin" >> $SENDER_CMD_FILE
      fi  
      #Last SK for debug purposes - if you take this out without removing debugging decryption, there will be a crash
    fi
  fi  
  }
done  

#Now actually run the commands
if [ $EXECUTIVE -eq "1" ]; then
  echo "Running query at the site(s)..." 
fi
if [[ $PARALLEL -eq 1 ]]; then
  echo "Now running in parallel...":
  parallel --no-notice -t < $SENDER_ENCRYPT_CMD_FILE
  parallel --no-notice -t < $SENDER_CMD_FILE
else
  ALL_SENDER_COMMANDS=data/all_sender_commands.sh
  rm -f $ALL_SENDER_COMMANDS
  cat $SENDER_ENCRYPT_CMD_FILE $SENDER_CMD_FILE > $ALL_SENDER_COMMANDS
  bash $BASH_FLAGS $ALL_SENDER_COMMANDS
fi
if [ $EXECUTIVE -eq "1" ]; then
  echo -e "\tFinished running query at the site(s)" 
fi

#If we're only doing one site, then create n-1 ciphertexts of zero, and copy them to the appropriate filename
ZERO_CT=./bin/zero_ct
ZERO_FILE=./data/zero.ctext
$ZERO_CT -c $CONTEXT_FILE -p $PUBLIC_KEY_FILE -e $EVK_FILE -t $TYPE > $ZERO_FILE
if [ $PRECOMPUTE -eq "1" ] && [ $ONE_SITE -eq "1" ]; then
  if [ $EXECUTIVE -eq "1" ]; then
    echo "Generating null results (for saving time during the demo)..." 
  fi
  for ((j=0; j<NUM_PARTIES; j++)); do
    for ((i=0; i<NUM_PARTITIONS; i++)); do
      if [ $j -ne "0" ]; then
        cp $ZERO_FILE data/result_${i}_${j}.ctext
        #echo "Wrote a zero ciphertext to data/result_${i}_${j}.ctext" #DEBUG statement
      fi  
    done
  done
  if [ $EXECUTIVE -eq "1" ]; then
    echo -e "\tFinished generating null results." 
  fi
fi  


SITE_DECRYPT_CMDS=data/site_decrypt_commands.sh
rm -rf $SITE_DECRYPT_CMDS
RESULTS_FILE_LIST=data/result_files.txt
#Post-intersection calculation computation occurs here
if [ $ONLINE -eq 1 ]; then
  if [ $EXECUTIVE -eq "1" ]; then
    echo "Aggregating results from all $NUM_PARTIES sites..." 
  fi
  #Aggregate
  if [ "$TYPE" = "CKKS" ]; then
    NUM_PARTITIONS=1 #Set this for easier aggregation later
    #Aggregate all data, across partitions and sites
    rm -f data/aggregated_0.dat
    #cat data/result*.ctext > data/combined_0.ctext
    find data -type f -name 'result_*.ctext' > $RESULTS_FILE_LIST
    #Only read NUM_PARTIES here, as with SPSI we have 1 "partition" after the intersection calculation
    ./bin/aggregate < $RESULTS_FILE_LIST $KEY_FILE_ARGS_NO_PRIVKEY -r data/privatekey_0.bin -t $TYPE -m $(( $NUM_PARTIES )) > data/aggregated_0.ctext
  else
    rm -f data/combined_*.ctext
    #For APSI-esque PSI, keep partitions separate
    #WARNING: this loop is not parallelizeable as written. To make it so, have separate RESULTS_FILE_LIST for each iteration.
    for ((i=0; i<NUM_PARTITIONS; i++)); do
      find data -type f -name 'result_*.ctext' > $RESULTS_FILE_LIST
      ./bin/aggregate < $RESULTS_FILE_LIST $KEY_FILE_ARGS_NO_PRIVKEY -t $TYPE -m $NUM_PARTIES > data/aggregated_${i}.ctext
    done
  fi
  if [ $EXECUTIVE -eq "1" ]; then
    echo -e "\tFinished aggregating results from all $NUM_PARTIES sites." 
  fi

  #Results are now in data/aggregated_${partition_idx}.dat
  #Partial decryption if we have more than 1 party
  if (($NUM_KEY_SHARES > 1)); then
    if [ $EXECUTIVE -eq "1" ]; then
      echo "Starting distributed decryption for $NUM_KEY_SHARES key shares..." 
    fi
    for ((j=0; j<NUM_KEY_SHARES; j++)); do
      for ((i=0; i<NUM_PARTITIONS; i++)); do
        #echo "Site decryption for party $j partition $i"
        echo "./bin/site_decrypt $KEY_FILE_ARGS_NO_PRIVKEY -r data/privatekey_${i}.bin < data/aggregated_${i}.ctext > data/partial_dec_${i}_${j}.par" >> $SITE_DECRYPT_CMDS
        echo "echo -e '\tFinished partial decryption for key share $j, partition $i'" >> $SITE_DECRYPT_CMDS 
      done
    done
    if [[ $PARALLEL -eq 1 ]]; then
      parallel -t < $SITE_DECRYPT_CMDS
      else  
        bash $BASH_FLAGS $SITE_DECRYPT_CMDS
       fi     
  else  
    for ((i=0; i<NUM_PARTITIONS; i++)); do
      mv data/aggregated_${i}.ctext data/partial_dec_${i}_0.par
    done
  fi  
  if [ $EXECUTIVE -eq "1" ]; then
    echo -e "\tFinished distributed decryption for $NUM_KEY_SHARES key shares." 
  fi
  

  #If using APSI, print results for every partition
  #If using SPSI, print result for single aggregated ciphertext
  #Again, include -s 1 -e evalkeys.bin as dummy arguments
  DECRYPT_KEY="-r data/privatekey_0.bin"
  if (($NUM_PARTIES > 1)); then
    DECRYPT_KEY_FILE=""
  fi
  #echo $DECRYPT_KEY

  if [ $EXECUTIVE -eq "1" ]; then
    echo "Decoding result..."
  fi
  DECODED_RESULT=0
  if [ "$TYPE" = "BFV" ]; then
    # Variable to store the sum of outputs
    #sum=0
    # Run the program k times
    for ((i=0; i<NUM_PARTITIONS; i++)); do
      # Run the program and capture the output 
      cat data/partial_dec_${i}_*.par > data/tmp.par
      DECODED_RESULT=$(bin/receiver -t $TYPE -q $KEY_FILE_ARGS_NO_PRIVKEY $DECRYPT_KEY -s 1 -n $NUM_KEY_SHARES < data/tmp.par )
      echo -e "\tResult for partition $i is $DECODED_RESULT"
      # Add the output to the sum
      #sum=$((sum + output))
    done
    #[ $sum -ne 0 ] && echo "Intersection" || echo "No intersection"
  else
    cat data/partial_dec_0_*.par > data/tmp.par
    DECODED_RESULT=$(bin/receiver -s 1 -t $TYPE -q $KEY_FILE_ARGS_NO_PRIVKEY $DECRYPT_KEY -n $NUM_KEY_SHARES < data/tmp.par )
    echo -e "\tDecoded result is $DECODED_RESULT"
  fi
fi #end online computation
if [ $EXECUTIVE -eq "1" ]; then
  if [ $DECODED_RESULT -ne "0" ]; then
    echo "Query $EMAIL FOUND in database!"
  else
    echo "Query $EMAIL NOT FOUND in database!"
  fi
  echo "All operations finished."
fi
