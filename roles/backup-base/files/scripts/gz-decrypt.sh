#!/bin/bash
#set -x

INFILE="$1"
OUTFILE="$2"

CIPHER="aes-256-cbc"
# explicitly set message digest becase defaults have changed
# openssl 1.0.x uses MD5 but openssl 1.1.x uses SHA256
MDSUM="sha256"

if [ -z "$INFILE" -o -z "$CRYPTOPASS" ]; then
    echo "usage: CRYPTOPASS=<secret> $(basename $0) <file> [<outfile> | -]" 1>&2
    echo "note: if <outfile> is not provided, input file is decrypted in-place"
    exit 1
fi

if [ -z "$OUTFILE" ]; then
    OUTFILE="$INFILE"
fi

export CRYPTOPASS

DEC_ARGS="$CIPHER -d -salt -base64 -pass env:CRYPTOPASS -md $MDSUM"

if [ "$INFILE" = "-" ]; then
    openssl $DEC_ARGS | gzip -cd
elif [ "$OUTFILE" = "-" ]; then
    openssl $DEC_ARGS < "$INFILE" | gzip -cd
else
    TMPFILE="$(mktemp)"

    function finish {
        rm -rf $TMPFILE
    }

    trap finish EXIT

    openssl $DEC_ARGS < "$INFILE" | gzip -cd > "$TMPFILE" && \
    cat < "$TMPFILE" > "$OUTFILE"
fi

exit $?
