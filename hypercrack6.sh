#!/usr/bin/env bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied, please supply the json file to crack (the output of nsec3enum.py)"
    exit 1
fi


groups="a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9"

for i in ${groups}
do
   ./rust/target/release/brute_sublist $i | ./rust/target/release/brute $1 &
done

for i in ${groups}
do
   wait
done

# ./rust/target/release/brute_sublist

# read -p $'Press Enter to quit\n\n'
# killall brute_sublist