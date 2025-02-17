#!/bin/bash

#echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial main restricted" | sudo tee -a /etc/apt/sources.list && \
apt-get update && \
    apt-get install -y git make autoconf automake libtool pkg-config \
        zlib1g-dev libjpeg-dev libopenjp2-7-dev libpng-dev libcairo2-dev \
        libtiff-dev liblcms2-dev libboost-dev wget

wget https://github.com/Kitware/CMake/releases/download/v3.31.5/cmake-3.31.5-linux-x86_64.tar.gz
tar zxf cmake-3.31.5-linux-x86_64.tar.gz
cd cmake-3.31.5-linux-x86_64
cp * -fr -t /usr
