#!/bin/bash
NFTHOME=/home/klh10/nft-dnschaos
NFTARGS="-d -c 10.1.1.72"

# Activate venv
source $NFTHOME/bin/activate

# run with args
$NFTHOME/bin/python3 $NFTHOME/nft-dnschaos.py $NFTARGS
