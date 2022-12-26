#!/bin/sh
python3 src/gossip_mockup.py -a 127.0.0.1 -p 7001 &
gossip_pid=$!
python3 src/test_module.py &
test_pid=$!
trap onexit INT
onexit () {
  kill -9 $gossip_pid
  kill -9 $test_pid
 }
echo "Gossip and testing module started; waiting 20 seconds before starting NSE"
sleep 20s
python3 src/nse.py