#!/bin/bash
#set -x

INFILE="$1"
OUTFILE="$2"

CIPHER="aes-256-cbc"
# explicitly set message digest becase defaults have changed
# openssl 1.0.x uses MD5 but openssl 1.1.x uses SHA256
# see https://github.com/fastlane/fastlane/issues/9542
MDSUM="sha256"

if [ -z "$INFILE" ] || [ -z "$AESPASS" ]; then
    echo "usage: AESPASS=<secret> $(basename "$0") <file> [<file>.gz.enc | -]" 1>&2
    echo "note: if <outfile> is not provided, input file is encrypted to <file>.gz.enc" 1>&2
    exit 1
fi

if [ -z "$OUTFILE" ]; then
    OUTFILE="$INFILE.gz.aes"
fi

export AESPASS

ENC_ARGS="$CIPHER -e -salt -base64 -pass env:AESPASS -md $MDSUM"

if [ "$INFILE" = '-' ]; then
    # shellcheck disable=SC2086
    gzip -c | openssl $ENC_ARGS
elif [ "$OUTFILE" = '-' ]; then
    # shellcheck disable=SC2086
    gzip -c < "$INFILE" | openssl $ENC_ARGS
else
    TMPFILE="$(mktemp)"

    function finish {
        rm -rf "$TMPFILE"
    }

    trap finish EXIT

    # shellcheck disable=SC2086
    gzip -c < "$INFILE" | openssl $ENC_ARGS > "$TMPFILE" && \
    cat < "$TMPFILE" > "$OUTFILE"
fi

exit $?
