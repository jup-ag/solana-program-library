#!/bin/bash

apt update
apt install -y wget git curl gcc pkg-config libudev-dev make clang cmake libssl-dev ninja-build
curl https://sh.rustup.rs -sSf | sh -s -- -y
. $HOME/.cargo/env

if [[ "$(uname -m)" == "x86_64" ]] ; then
    sh -c "$(curl -sSfL https://release.solana.com/v1.10.28/install)"
    wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
    dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
else
    git clone https://github.com/solana-labs/solana.git --branch v1.10.28
    cd solana
    ./scripts/cargo-install-all.sh .
    ln -s /usr/bin/python3 /usr/bin/python
    cd /
    git clone https://github.com/solana-labs/bpf-tools.git --branch v1.27
    cd /bpf-tools
    sed -i 's/HOST_TRIPLE=x86_64-unknown-linux-gnu/if [[ "$(uname -m)" == "aarch64" ]] ; then HOST_TRIPLE=aarch64-unknown-linux-gnu; else HOST_TRIPLE=x86_64-unknown-linux-gnu; fi;/g' build.sh
    ./build.sh
    mkdir -p  ~/.cache/solana/v1.27/bpf-tools/
    cp solana-bpf-tools-linux.tar.bz2 ~/.cache/solana/v1.27/bpf-tools/
    cd ~/.cache/solana/v1.27/bpf-tools/
    tar -xf solana-bpf-tools-linux.tar.bz2
    rm -rf /bpf-tools/
fi
