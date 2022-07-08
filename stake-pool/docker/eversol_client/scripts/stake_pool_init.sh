#!/bin/bash

spl-stake-pool create-pool --epoch-fee-numerator 1 \
    --epoch-fee-denominator 400 \
    --max-referrers 255 \
    --max-validators 25 \
    --deposit-fee-numerator 1 \
    --deposit-fee-denominator 400 \
    --with-community-token \
    --pool-keypair $STAKE_POOL_KEY \
    --reserve-keypair $RESERVE_KEY \
    --mint-keypair $MINT_KEY \
    --treasury-keypair $TREASURY_KEY
    