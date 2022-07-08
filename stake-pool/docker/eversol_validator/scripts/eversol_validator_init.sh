#!/bin/bash

solana-test-validator --slots-per-epoch 1024 &
sleep 5
solana config set --url localhost
solana config set -k $MANAGER_KEY
solana airdrop 500

solana program deploy /solana-program-library/target/deploy/spl_stake_pool.so --program-id $STAKE_POOL_PROGRAM_KEY
sleep inf