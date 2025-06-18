#!/bin/sh
## Copyright © 2023-2024 Björn Victor (bjorn@victor.se)
## Script to fetch a fresh CRL file if needed. Run it periodically, e.g. every night.

## arg: the cbridge.conf file
# to use to find CRL file name, ca-bundle, and cert
# If the crl file doesn't exist, (NYI: or it doesn't verify), (NYI: or if given a bootstrap URL),
# unconditionally fetch a new crl file from the url,
# otherwise fetch one if it is newer than the existing file.
# (Don't compare to "last updated" property of CRL,
# since the FILE at the distribution point most likely is always later.)

INPUT=$1
if [ "X$INPUT" = "X" ]; then
    INPUT=./cbridge.conf
fi
if [ ! -r $INPUT ]; then
    echo cbridge config file $INPUT not found
    exit 1
fi

TLSCONF=$(grep -v '^;' $INPUT | grep ^tls)

if [ "X$TLSCONF" = "X" ]; then
    echo No TLS configuration found in $INPUT
    exit 1
fi

INDIR=$(dirname $INPUT)

INCRL=$(echo $TLSCONF | grep crl | sed -E 's/.* crl ([^ ]+)( .*)?/\1/' )
CERT=$(echo $TLSCONF | grep cert | sed -E 's/.* cert ([^ ]+)( .*)?/\1/' )
CABUNDLE=$(echo $TLSCONF | grep ca-chain | sed -E 's/.* ca-chain ([^ ]+)( .*)?/\1/' )
if [ "X$CABUNDLE" = "X" ]; then
    # Not found, use default name
   CABUNDLE=ca-chain.cert.pem
fi
CABUNDLE=$INDIR/$CABUNDLE

if [ "X$INCRL" = "X" ]; then
    echo Error: no crl file configured
    exit 1
fi
INCRL=$INDIR/$INCRL
if [ "X$CERT" = "X" -o ! -f $INDIR/$CERT -o ! -r $INDIR/$CERT ]; then
    echo Error: cert file $CERT not found
    exit 1
fi
CERT=$INDIR/$CERT
if [ ! -f $CABUNDLE -o ! -r $CABUNDLE ]; then
    echo Error: CA bundle file not found
    exit 1
fi

OUTPUT=/tmp/$(basename $INCRL)

if [ -r $INCRL -a -s $INCRL ]; then
    url=$(openssl crl -in $INCRL -noout -text | grep URI: | sed -e 's/.*URI://')
    if [ "X$url" = "X" ]; then
	# Find DP from $CERT
	url=$(openssl x509 -in $CERT -noout -ext crlDistributionPoints | grep URI: | sed -e 's/.*URI://')
	if [ "X$url" = "X" ]; then
	    # DP not found in cert (ok if it is old) - use default
	    url=https://chaosnet.net/intermediate.crl.pem
	    echo Can not find CRL distribution point in $INCRL or $CERT, using default $url
	fi
    fi
    # Fetch a new copy if the creation date of the file on the server is newer than the one we already have,
    # or if our copy has expired.
    # (The lastupdate of a crl file will always be earlier than the creation time of the copy.)
    if [ $(uname) = "Darwin" ]; then
	# dateopt might be openssl3, and date requires format to parse date, and has other flags
	# last=$(openssl crl -in $INCRL -noout -lastupdate -dateopt iso_8601 | sed -e 's/.*=//')
	next=$(openssl crl -in $INCRL -noout -nextupdate -dateopt iso_8601 | sed -e 's/.*=//')
	nextstamp=$(/bin/date -j -f "%F %TZ" "$next" +"%s")
    elif [ $(uname) = "Linux" ]; then
	# Linux might be running openssl1 which doesn't have dateopt, but date parses dates more frely
	# last=$(openssl crl -in $INCRL -noout -lastupdate | sed -e 's/.*=//')
	next=$(openssl crl -in $INCRL -noout -nextupdate | sed -e 's/.*=//')
	nextstamp=$(/bin/date -d "$next" +"%s")
    fi
    rm -f $OUTPUT
    if [ $(/bin/date +"%s") -ge $nextstamp ]; then
	# Keep this script running and it shouldn't happen very often
	echo WARNING: The existing CRL file $INCRL has expired, fetching a new copy.
	# So always fetch a new one
	curl -S -s --output $OUTPUT $url
    else
	curl -S -s --time-cond $INCRL --output $OUTPUT $url
    fi
elif [ ! -d $INCRL ]; then
    echo CRL file $INCRL does not exist, fetching a fresh copy
    # Find DP from $CERT
    url=$(openssl x509 -in $CERT -noout -ext crlDistributionPoints | grep URI: | sed -e 's/.*URI://')
    if [ "X$url" = "X" ]; then
	# DP not found in cert (ok if it is old) - use default
	url=https://chaosnet.net/intermediate.crl.pem
    fi
    rm -f $OUTPUT
    curl -S -s --output $OUTPUT $url
else
    echo Error: Invalid CRL file setting $INCRL - is it a directory?
    exit 1
fi

if [ -r $OUTPUT -a -s $OUTPUT ]; then
    # We got something, check if it is OK
    if ! openssl crl -verify -noout -CAfile $CABUNDLE -in $OUTPUT 2>/dev/null; then
	echo The fetched CRL file could not be verified:
	# Now show the output
	openssl crl -verify -noout -CAfile $CABUNDLE -in $OUTPUT
	exit 1
    fi
    if [ $(uname) = "Darwin" ]; then
	nnext=$(openssl crl -in $OUTPUT -noout -nextupdate -dateopt iso_8601 | sed -e 's/.*=//')
	nnextstamp=$(/bin/date -j -f "%F %TZ" "$nnext" +"%s")
    elif [ $(uname) = "Linux" ]; then
	nnext=$(openssl crl -in $OUTPUT -noout -nextupdate | sed -e 's/.*=//')
	nnextstamp=$(date -d "$nnext" +"%s")
    fi
    if [ $(/bin/date +"%s") -ge $nnextstamp ]; then
	echo ERROR: The fetched CRL has expired already!
	exit 1
    fi
    num=$(openssl crl -in $OUTPUT -noout -crlnumber | sed -e 's/.*=//')
    mv $OUTPUT $INCRL.new
    if [ -r $INCRL -a -s $INCRL ]; then
	onum=$(openssl crl -in $INCRL -noout -crlnumber | sed -e 's/.*=//')
	mv $INCRL $INCRL.old.$onum
    fi
    mv $INCRL.new $INCRL
    echo CRL file updated - new CRL number $num
else
    echo No new CRL file fetched this time.
fi
