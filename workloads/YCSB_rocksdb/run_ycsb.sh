#!/bin/bash

# This shell script run YCSB workload a 10 times.
# To run this script...
# $ sudo bash ./run_ycsb.sh
# $ sudo bash ./run_ycsb.sh > ./luma_test_logs/scext4_2dev

echo "<YCSB RocksDB benchmark script>"
echo "load YCSB-a x1 & run YCSB-a x5.."

#function run
run() {
    echo "*---------------------------------- ycsb load ----------------------------------*"
    sleep 3 # sleep bash script for 3 second
    #sudo ./bin/ycsb load rocksdb -s -P workloads/workloada -p rocksdb.dir=/mnt/test  # No throttling (No qps control)
    #sudo ./bin/ycsb load rocksdb -s -P workloads/workloadf -p rocksdb.dir=/mnt/test -target 10000000 # Throttling (qps control: 10,000,000)
    #sudo ./bin/ycsb load rocksdb -s -P workloads/workloada -p rocksdb.dir=/mnt/test -target 100000000 # Throttling (qps control: 100,000,000)
    sudo ./bin/ycsb load rocksdb -s -P workloads/workloada -p rocksdb.dir=/mnt/test -p rocksdb.optionsfile=./configs/rocksdb_config.ini -target 100000000  # Throttling (qps control: 100,000,000), RocksDB config
    #sudo ./bin/ycsb load rocksdb -s -P workloads/workloada -P configs/config-run.dat -p rocksdb.dir=/mnt/test -target 2100000000  # UIUC config + Throttling (qps control)
    echo "*---------------------------------- ycsb load end ------------------------------*"
    #ierate=5
    #shift
    #for i in `seq $iterate`; do
    #for i in {1..5}; do
    for ((i=1;i<=5;i++)); do
    #for ((i=1;i<=10;i++)); do
      echo "*---------------------------------- ycsb run_$i ----------------------------------*"
      sleep 3 # sleep bash script for 3 second
      #sudo ./bin/ycsb run rocksdb -s -P workloads/workloada -p rocksdb.dir=/mnt/test   # No throttling (No qps control)
      #sudo ./bin/ycsb run rocksdb -s -P workloads/workloadf -p rocksdb.dir=/mnt/test -target 10000000  # Throttling (qps control: 10,000,000)
      #sudo ./bin/ycsb run rocksdb -s -P workloads/workloada -p rocksdb.dir=/mnt/test -target 100000000  # Throttling (qps control: 100,000,000)
      sudo ./bin/ycsb run rocksdb -s -P workloads/workloada -p rocksdb.dir=/mnt/test -p rocksdb.optionsfile=./configs/rocksdb_config.ini -target 100000000  # Throttling (qps control: 100,000,000), RocksDB config
      #sudo ./bin/ycsb run rocksdb -s -P workloads/workloada -P configs/config-run.dat -p rocksdb.dir=/mnt/test -target 2100000000  # UIUC config + Throttling (qps control)
# UIUC config + throttling (qps control)

      echo "*---------------------------------- ycsb run end ------------------------------*"
    done
}

run
echo "experiment end."
