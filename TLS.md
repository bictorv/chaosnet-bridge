# Chaos-over-TLS setup

With Chaos-over-TLS, the Chaosnet packets are sent over a [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) connection. 

One typical situation is that you already had a host (e.g. ITS or LISPM) or two connected by `chudp`, and now want to add a Chaosnet Bridge between your local Chaosnet and the global one. You need a local Chaosnet subnet (different from subnet 6) for your local traffic, and your `cbridge` needs an address on subnet 6 for the connection to the [Global Chaosnet](https://chaosnet.net).

There are different reasons to want to use TLS:
- one is for improved security (confidentiality, authenticity), and
- another is for clients which don't have externally reachable and
  stable IP addresses and thus are not reachable by UDP. TCP would
  suffice, but since clients don't have stable IPs, it would be hard to
  firewall - instead you need an open server which is not so
  nice/secure. TLS helps with authentication. 
- additionally, (sometimes) this type of connection seems to give a faster connection than Chaos-over-UDP.

When configured as a client using Chaos-over-TLS, you need a
certificate matching that of the server you're connecting to. Here's how.

To get a certificate for the Global Chaosnet, you need to do the following.

## Register

Unless you are already connected to the Global Chaosnet, register your cbridge with the DNS server: send the following info about it to Björn:
- the host name, including its domain. Do not invent domains, but use a domain you have permission to use. If you have none, use "Chaosnet.net".

If you were not already connected, Björn will assign a Chaosnet address for you on subnet 6.

## Create a Certificate Request

Create a Certificate Request by using the following command (one line):

    openssl req -new -newkey rsa:2048 -keyout my.key.pem -nodes -out my.csr.pem -subj "/C=SE/O=The Global Chaosnet/CN=my.fully-qualified-domain.on.chaosnet"

where "my.fully-qualified-domain.on.chaosnet" should not be taken literally, but should be your host name including domain that you used in the previous step (or already registered).

If you already have a key (e.g. in case you want to renew your certificate), instead use

    openssl req -new -key my.key.pem -nodes -out my.csr.pem -subj "/C=SE/O=The Global Chaosnet/CN=my.fully-qualified-domain.on.chaosnet"

1. Save the key file `my.key.pem` in a safe place, e.g. `chaosnet-bridge/private/my.key.pem`.
1. Send the file `my.csr.pem` to Björn, who will generate a certificate and send it back to you. Put it in a good place, e.g. `chaosnet-bridge/certs/my.cert.pem`.

## Configure cbridge

Add TLS configuration to your `cbridge.conf` file:

    tls key private/my.key.pem cert certs/my.cert.pem

*If* you were already connected over `chudp`, **remove** your old `link chudp router.chaosnet.net...` line.

Add the link configuration:

    link tls router.chaosnet.net host 3040 myaddr 3xxx

where 3xxx is the Chaosnet address on subnet 6 which you got from Björn.

## Restart cbridge

Restart `cbridge` and check that/if it works. Let Björn know!

(Of course you also need to configure your local Chaosnet.)

## How Björn creates your cert

Mostly so I remember (see also https://jamielinux.com/docs/openssl-certificate-authority/sign-server-and-client-certificates.html):

    openssl ca -config ../intermediate-ca.cnf -extensions usr_cert -days 375 -notext -md sha256 -in your.csr.pem -out certs/your.cert.pem

and for a combined client+server certificate

    openssl ca -config ../intermediate-ca.cnf -extensions usr_server_cert -days 375 -notext -md sha256 -in your.csr.pem -out certs/your.cert.pem
