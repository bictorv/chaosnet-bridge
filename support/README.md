# Support files

This directory contains support files for cbridge.

General configuration
- ca-chain.cert.pem - the certificate chain for joining the [Global Chaosnet](https://chaosnet.net/global).

Starting cbridge - these files **NEED EDITING** for your local path to cbridge
- cbridge.service - systemd service (for e.g. Linux)
  - cbridge-starter.sh - starter script used by cbridge.service
    - cbridge-starter-services.sh - service starter script used by cbridge-starter.sh
    - cbridge-services.conf - config file used by cbridge-starter-services.sh
  - firewall.sh - a script which adds simple packet filtering using iptables, run by cbridge.service
- net.chaosnet.cbridge.plist - plist for launchd (for e.g. macOS)

Keeping the CRL (certificate revocation list) up-to-date. These may also **NEED EDITING**.
- cbridge-crl-update.timer - systemd timer, which periodically runs cbridge-crl-update.service
- cbridge-crl-update.service - systemd service, which is run by cbridge-crl-update.timer
- crl-update.sh - script which updates the CRL file, run by cbridge-crl-update.service

Services. You will need to **READ AND EDIT** these to your local circumstances.
- cbfile-server.service - runs the FILE server provided [here](https://tumbleweed.nu/r/chaos/dir?ci=tip&name=chcbridge).
- chaosnet-rtape.service - runs the RTAPE server provided [here](https://github.com/Chaosnet/chaosnet-tools).
- nft-dnschaos.service - runs an [NFT packet filtering](https://wiki.nftables.org/wiki-nftables) script to support Chaosnet DNS (e.g. from TOPS-20)
  - nft-dnschaos.sh - runs the DNS NFT program, see below
  - nft-dnschaos.py - Python program to set up DNS packet filtering to send Chaosnet-class DNS queries to a separate DNS server
- klh10-nftables.service - installs another NFT packet filtering program to support running multiple klh10 instances on one machine, and to support/use the nft-dnschaos program (otherwise not very related to Chaosnet).
  - klh10-nftables.conf - the NFT program.

Other
- chaos.lua - a "dissector" which can be used to show Chaosnet packets in [Wireshark/tshark](https://www.wireshark.org/). Needs to be installed in the right place, see comment at start.

