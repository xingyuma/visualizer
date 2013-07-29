#!/bin/bash


echo "Start..."

cat ./asn1-1.0.js \
./asn1hex-1.1.js \
./asn1x509-1.0.js \
./crypto-1.1.js \
./ecparam-1.0.js \
./pkcs5pkey-1.0.js \
./rsapem-1.1.js \
./rsasign-1.2.js \
./ecdsa-modified-1.0.js \
./x509-1.1.js \
 > jsr-lib.js


echo "Done."