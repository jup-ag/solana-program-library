FROM ubuntu
LABEL one.eversol.solana eversol solana container based on solana-cli v1.10.28

RUN apt update && \
    apt install -y wget git curl gcc pkg-config libudev-dev make clang cmake libssl-dev ninja-build && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    . $HOME/.cargo/env && \
    git clone https://github.com/solana-labs/solana.git --branch v1.10.28 && \
    cd solana && \
    ./scripts/cargo-install-all.sh . && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    cd / && \
    git clone https://github.com/solana-labs/bpf-tools.git --branch v1.27 && \
    cd /bpf-tools && \
    sed -i 's/HOST_TRIPLE=x86_64-unknown-linux-gnu/if [[ "$(uname -m)" == "aarch64" ]] ; then HOST_TRIPLE=aarch64-unknown-linux-gnu; else HOST_TRIPLE=x86_64-unknown-linux-gnu; fi;/g' build.sh && \
    ./build.sh && \
    mkdir -p  ~/.cache/solana/v1.27/bpf-tools/ && \
    cp solana-bpf-tools-linux.tar.bz2 ~/.cache/solana/v1.27/bpf-tools/ && \
    cd ~/.cache/solana/v1.27/bpf-tools/ && \
    tar -xf solana-bpf-tools-linux.tar.bz2 && \
    rm -rf /bpf-tools/

ENV PATH=/solana/bin:$PATH
COPY keys/stake_pool_program.json /root/stake_pool_program.json

# Uncomment the following line to update eversol program
ARG CACHEBUST=1
RUN git clone https://github.com/everstake/solana-program-library.git && \
    cd solana-program-library/stake-pool/program/ && \
    sed -i "s/declare_id!(\"[^\"]*/declare_id!(\"$(solana address -k /root/stake_pool_program.json)/" src/lib.rs && \
    . /root/.cargo/env && \
    cargo build-bpf