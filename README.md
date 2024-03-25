# ScaleCache: A Scalable Page Cache for Multiple Solid-State Drives [EuroSys '24] 

This repository contains the artifact for reproducing our EuroSys '24 paper "ScaleCache: A Scalable Page Cache for Multiple Solid-State Drives". <!-- A website of this repository is at [here](https://rs3lab.github.io/Odinfs/). -->

# Table of Contents
* [Overview](#overview)
* [Setup](#setup)
* [Authors](#authors)

# Overview 

### Structure:

```
root
|---- fs                 (source code of the evaluated file systems)
    |---- scext4         (ScaleCache ext4 kernel module)
    |---- scxfs          (ScaleCache xfs kernel module)
|---- kernel             (5.4.147 Linux kernel)
|---- workloads          (evaluation workloads)
    |---- ffsb           (The Flexible Filesystem Benchmark)
    |---- filebench      (Filebench: mailserver, fileserver, videoserver) 
    |---- fio            (fio scripts)
    |---- scripts        (main evaluation scripts)
    |---- sysbench       (sysbench)
    |---- YCSB_memcached (Yahoo! Cloud Serving Benchmark: Memcached) 
    |---- YCSB_rocksdb   (Yahoo! Cloud Serving Benchmark: RocksDB)  
```

### Environment: 

Our artifact should run on any Linux distribution. The current scripts are developed for **Ubuntu 20.04.3 LTS**. <!-- Porting to other Linux distributions would require some scripts modifications , especially ```dep.sh```, which installs dependencies with package management tools. -->

# Setup 

**Note**: For the below steps, our scripts will complain if it fails to compile or install the target. Check the end part of the scripts' output to ensure that the install is successful. Also, some scripts would prompt to ask the sudo permission at the beginning. 

### 1. Install the dependencies:
```bash
$ ./dep.sh 
```

### 1. Install the 5.4.147-ScaleCache Linux kernel (50GB space and 20 minutes)
```bash
$ cd kernel
$ cp config-scalecache .config
$ make oldconfig             (update the config with the provided .config file)
```
<!--
Say N to KASAN if the config program prompts to ask about it. 

```
KASAN: runtime memory debugger (KASAN) [N/y/?] (NEW) N
```
-->

Next, please use your favorite way to compile and install the kernel. The below step is just for reference. The installation requires 50GB space and takes around 20 minutes on our machines. 

The classical ways will work as well:
```bash
$ make -j64              
$ make -j64 modules 
$ sudo make -j64 modules_install
$ sudo make -j64 install
```
Reboot the machine to the installed 5.4.147-ScaleCache kernel. 

### 3. Install and insmod file systems 

```bash
$ cd scext4
$ make -j64
$ make install
$ sudo modprobe jbd3
$ sudo modprobe scext4
$ sudo mount -t scext4 DEVICE MOUNTPOINT
```
The script will compile, install, and insert the following kernel modules:

* jbd3 
* scext4

### 4. Compile and install benchmarks 

**4.1 FFSB**

```
$ cd workloads/ffsb
$ ./compile.sh
```

**4.2 Filebench**

```
$ cd workloads/filebench
$ ./compile.sh
```

**4.3 sysbench**

```
$ cd workloads/sysbench
$ ./compile.sh
```

**4.4 YCSB**

```
$ cd workloads/YCSB_memcached
$ ./compile.sh
```

# Authors

Kiet Tuan Pham (Chung-Ang University)

Seokjoo Cho (Chung-Ang University)

Sangjin Lee (Chung-Ang University)

Lan Anh Nguyen (Chung-Ang University)

Hyeongi Yeo (Chung-Ang University)

Ipoom Jeong (University of Illinois Urbana-Champaign)

Sungjin Lee (DGIST)

Nam Sung Kim (University of Illinois Urbana-Champaign)

Yongseok Son (Chung-Ang University) 
