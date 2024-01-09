#!/bin/bash

# This shell script run YCSB workload a 5 times.
# To run this script...
# $ sudo bash ./run_ycsb.sh
# $ sudo bash ./run_ycsb.sh > ./luma_test_logs/scext4_2dev

# before running the script please check Memcached-
# configuration file(/etc/memcached.conf) if the maximum item size is > 20m [-I 20m] needed.

echo "<YCSB Memcached benchmark script>"
echo "load YCSB-a x1 & run YCSB-a x5..."

#function run
run() {
    echo "*---------------------------------- ycsb load ----------------------------------*"
    #sleep 3 # sleep bash script for 3 second
    #sudo ./bin/ycsb load rocksdb -s -P workloads/workloadf -p rocksdb.dir=/mnt/test
    sudo ./bin/ycsb load memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1"
    echo "*---------------------------------- ycsb load end ------------------------------*"
    #ierate=5
    #shift
    #for i in `seq $iterate`; do
    #for i in {1..5}; do
    for ((i=1;i<=5;i++)); do
      echo "*---------------------------------- ycsb run_$i ----------------------------------*"
      #sleep 3 # sleep bash script for 3 second
      #sudo ./bin/ycsb run rocksdb -s -P workloads/workloadf -p rocksdb.dir=/mnt/test
      sudo ./bin/ycsb run memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1"
      echo "*---------------------------------- ycsb run end ------------------------------*"
    done
}

run
echo "experiment end."
