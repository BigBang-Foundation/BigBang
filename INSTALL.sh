#!/bin/bash

origin_path=$(cd `dirname $0`; pwd)
cd `dirname $0`

# create build directory
if [ ! -d "build/" ]; then
    mkdir build
fi

# go to build
cd build

# cmake
flagdebug=""
if [[ "$1" = "debug" || "$2" = "debug" || "$3" = "debug" ]]
then
    flagdebug="-DCMAKE_BUILD_TYPE=Debug"
else
    flagdebug="-DCMAKE_BUILD_TYPE=Release"
fi

flagtestnet=""
if [[ "$1" = "testnet" || "$2" = "testnet" || "$3" = "testnet" ]]
then
    flagtestnet="-DTESTNET=on"
else
    flagtestnet="-DTESTNET=off"
fi

flagarm64crypto=''
if [[ "$1" = "arm64crypto" || "$2" = "arm64crypto" || "$3" = "arm64crypto" ]]
then
    flagarm64crypto="-DARM_CRYPTO=on"
else
    flagarm64crypto="-DARM_CRYPTO=off"
fi

cmake .. $flagdebug $flagtestnet $flagarm64crypto
if [ $? -ne 0 ]; then 
    cd $origin_path
    exit 1 
fi 

# make & install
os=`uname`
if [ "$os" == "Darwin" ]; then
    cores=`sysctl -n hw.logicalcpu`
    if [ "${cores}" == "" ]; then
        cores = 1
    fi
    echo "make install -j${cores}"
    make install -j${cores}
    
    if [ $? -ne 0 ]; then   
        exit 1 
    fi
else
    cores=`nproc --all`
    if [ "${cores}" == "" ]; then
        cores = 1
    fi
    echo "make -j${cores}"
    make -j${cores}

    if [ $? -ne 0 ]; then   
        exit 1 
    fi 

    echo "sudo make install"
    sudo make install
fi

cd $origin_path
