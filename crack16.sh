#!/usr/bin/env bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied, please supply the json file to crack"
    exit 1
fi


# array="0.fifo 1.fifo 2.fifo 3.fifo 4.fifo"
array="0.fifo 1.fifo 2.fifo 3.fifo 4.fifo 5.fifo 6.fifo 7.fifo 8.fifo 9.fifo a.fifo b.fifo c.fifo d.fifo e.fifo f.fifo"
# array="0.fifo 1.fifo 2.fifo 3.fifo 4.fifo 5.fifo 6.fifo 7.fifo 8.fifo 9.fifo a.fifo b.fifo c.fifo d.fifo e.fifo"

for i in ${array}
do
	mkfifo $i || false
done

# pid = $$

for i in ${array}
do
	 ./rust/target/release/brute $1 < $i &
done

./rust/target/release/brute_sublist | ./rust/target/release/mux ${array}

# read -p $'Press Enter to quit\n\n'
# killall brute_sublist