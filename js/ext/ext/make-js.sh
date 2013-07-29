#!/bin/bash


echo "Start..."

cat ./base64.js \
 ./md5.js \
./rsa2.js \
./prng4.js \
./sha1.js \
./base64.js \
./ripemd160.js \
./sha256.js \
./jsbn.js \
./rng.js \
./sha512.js \
./jsbn2.js \
./rsa.js \
  > ext.js


echo "Done."