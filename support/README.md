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
- cbridge-crl-update.service - systemd service, which is run by cbridge-crl-update.timer
- cbridge-crl-update.timer - systemd timer, which periodically runs cbridge-crl-update.service
- crl-update.sh - script which updates the CRL file, run by cbridge-crl-update.service

Other
- chaos.lua - a "dissector" which can be used to show Chaosnet packets in [Wireshark/tshark](https://www.wireshark.org/). Needs to be installed in the right place, see comment at start.

