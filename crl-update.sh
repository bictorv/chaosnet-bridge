#/bin/sh
## Copyright © 2023 Björn Victor (bjorn@victor.se)
## Script to fetch a fresh CRL file if needed. Run it periodically, e.g. every night.

## arg: the cbridge.conf file
# to use to find CRL file name, ca-bundle, and cert
# If the crl file doesn't exist, (NYI: or it doesn't verify), (NYI: or if given a bootstrap URL),
# unconditionally fetch a new crl file from the url,
# otherwise fetch one if it is newer than the existing file.
# (Don't compare to "last updated" property of CRL,
# since the FILE at the distribution point most likely is always later.)

INPUT=$1
if [ "X$INPUT" == "X" ]; then
    INPUT=./cbridge.conf
fi
if [ ! -r $INPUT ]; then
    echo cbridge config file $INPUT not found
    exit 1
fi

TLSCONF=$(grep -v '^;' $INPUT | grep ^tls)

if [ "X$TLSCONF" == "X" ]; then
    echo No TLS configuration found in $INPUT
    exit 1
fi

INDIR=$(dirname $INPUT)

INCRL=$INDIR/$(echo $TLSCONF | grep crl | sed -E 's/.* crl ([^ ]+)( .*)?/\1/' )
CERT=$INDIR/$(echo $TLSCONF | grep cert | sed -E 's/.* cert ([^ ]+)( .*)?/\1/' )
CABUNDLE=$(echo $TLSCONF | grep ca-chain | sed -E 's/.* ca-chain ([^ ]+)( .*)?/\1/' )
if [ "X$CABUNDLE" == "X" ]; then
    # Not found, use default name
   CABUNDLE=ca-chain.cert.pem
fi
CABUNDLE=$INDIR/$CABUNDLE

if [ "X$CERT" == "X" -o ! -r $CERT ]; then
    echo Error: cert file $CERT not found
    exit 1
fi
if [ ! -r $CABUNDLE ]; then
    echo Error: CA bundle file not found
    exit 1
fi

OUTPUT=/tmp/$(basename $INCRL)

if [ -r $INCRL ]; then
    next=$(openssl crl -in $INCRL -noout -nextupdate -dateopt iso_8601 | sed -e 's/.*=//')
    last=$(openssl crl -in $INCRL -noout -lastupdate -dateopt iso_8601 | sed -e 's/.*=//')
    # Needed for curl to parse it
    # rlast=$(openssl crl -in $INCRL -noout -lastupdate -dateopt rfc_822 | sed -e 's/.*=//')
    url=$(openssl crl -in $INCRL -noout -text | grep URI: | sed -e 's/.*URI://')

    # echo CRL last updated $last, next $next, URL $url

    if [ $(date +"%s") -ge $(date -j -f "%F %TZ" "$next" +"%s") ]; then
	# Keep this script running and it shouldn't happen very often
	echo WARNING: The CRL $INCRL has expired!
    fi
    # Fetch a new copy if it is newer
    rm -f $OUTPUT
    curl -S -s --time-cond $INCRL --output $OUTPUT $url
else
    echo CRL file $INCRL does not exist, fetching a fresh copy
    # Find DP from $CERT
    url=$(openssl x509 -in $CERT -noout -ext crlDistributionPoints | grep URI: | sed -e 's/.*URI://')
    if [ "X$url" == "X" ]; then
	# DP not found in cert (ok if it is old) - use default
	url=https://chaosnet.net/intermediate.crl.pem
    fi
    rm -f $OUTPUT
    curl -S -s --output $OUTPUT $url
fi

if [ -r $OUTPUT ]; then
    # We got something, check if it is OK
    if ! openssl crl -verify -noout -CAfile $CABUNDLE -in $OUTPUT 2>/dev/null; then
	echo The fetched CRL file could not be verified:
	# Now show the output
	openssl crl -verify -noout -CAfile $CABUNDLE -in $OUTPUT
	exit 1
    fi
    nnext=$(openssl crl -in $OUTPUT -noout -nextupdate -dateopt iso_8601 | sed -e 's/.*=//')
    if [ $(date +"%s") -ge $(date -j -f "%F %TZ" "$nnext" +"%s") ]; then
	echo ERROR: The fetched CRL has expired already!
    else
	num=$(openssl crl -in $OUTPUT -noout -crlnumber | sed -e 's/.*=//')
	[ -r $INCRL ] && onum=$(openssl crl -in $INCRL -noout -crlnumber | sed -e 's/.*=//')
	mv $OUTPUT $INCRL.new
	[ -r $INCRL ] && mv $INCRL $INCRL.old.$onum
	mv $INCRL.new $INCRL
	echo CRL file updated - new CRL number $num - please restart cbridge!
    fi
fi
    

