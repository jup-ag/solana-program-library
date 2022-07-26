FROM ubuntu
LABEL one.eversol.solana eversol solana container based on solana-cli v1.10.28

COPY common/scripts/install_tools.sh /install_tools.sh
RUN bash /install_tools.sh

ENV PATH=/root/.local/share/solana/install/active_release/bin:/solana/bin:$PATH
COPY keys/stake_pool_program.json /root/stake_pool_program.json

# Uncomment the following line to update eversol program
ARG CACHEBUST=1
RUN git clone https://github.com/everstake/solana-program-library.git && \
    cd solana-program-library/stake-pool/program/ && \
    sed -i "s/declare_id!(\"[^\"]*/declare_id!(\"$(solana address -k /root/stake_pool_program.json)/" src/lib.rs && \
    . /root/.cargo/env && \
    cargo build-bpf
