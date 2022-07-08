#!/bin/bash

solana config set --url http://eversol_validator:8899
solana config set -k $MANAGER_KEY
bash /scripts/stake_pool_init.sh
sleep inf