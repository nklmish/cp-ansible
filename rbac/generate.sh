#!/bin/bash -e

[ ! -f mds.key ] \
    && openssl genrsa -out mds.key 2048 \
    && rm -f mds.pub \
    && echo "mds.key generated"

[ ! -f mds.pub ] \
    && openssl rsa -in mds.key -outform PEM -pubout -out mds.pub \
    && echo "mds.pub generated"

