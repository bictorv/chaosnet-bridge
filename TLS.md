# Chaos-over-TLS setup

There are different reasons to want to use TLS:
- one is for improved security (confidentiality, authenticity), and
- another is for clients which don't have externally reachable and
  stable IP addresses and thus are not reachable by UDP. TCP would
  suffice, but since clients don't have stable IPs, it would be hard to
  firewall - instead you need an open server which is not so
  nice/secure. TLS helps with authentication. 

When configured as a client using Chaos-over-TLS, you need a
certificate matching that of the server you're connecting to. Here's how.

To get a certificate for the [Global Chaosnet](https://aosnet.ch), you need the following:

## Register

Unless you are already connected to the Global Chaosnet, register your host with the DNS server: send the following info about your Chaosnet host to Björn:
1. the host name, including its domain. Do not invent domains, but use a domain you have permission to use. If you have none, use "aosnet.CH".
1. the OS type (e.g. ITS or LISPM) and the system type (e.g. KLH10 or LAMBDA)

If you were not already connected, Björn will assign a Chaosnet address for you on subnet 6.

## Create a Certificate Request

Create a Certificate Request by using the following command (one line):

    openssl req -new -newkey rsa:2048 -keyout my.key.pem -nodes -out my.csr.pem -subj "/C=SE/O=The Global Chaosnet/CN=my.fully-qualified-domain.on.chaosnet"

where "my.fully-qualified-domain.on.chaosnet" should not be taken literally, but should be your host name including domain that you used in the previous step (or already registered).

1. Save the key file `my.key.pem` in a safe place, e.g. `chaosnet-bridge/private/my.key.pem`.
1. Send the file `my.csr.pem` to Björn, who will generate a certificate and send it back to you. Put it in a good place, e.g. `chaosnet-bridge/certs/my.cert.pem`.

## Configure cbridge

Add TLS configuration to your `cbridge.conf` file:

    tls key private/my.key.pem cert certs/my.cert.pem

If you were already connected over `chudp`, remove your old `link chudp router.aosnet.ch...` line.

Add the link configuration:

    link tls router.aosnet.ch host 3040 myaddr 3xxx

## Restart cbridge

Restart `cbridge` and check that/if it works. Let Björn know!
