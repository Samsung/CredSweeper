#!/usr/bin/env bash

set -ex

rm -f pkcs1.* pkcs8.* pkcs12.* asn1.*

# PKCS8
openssl genpkey -algorithm RSA -out pkcs8.key.pem -pkeyopt rsa_keygen_bits:512
openssl pkey -in pkcs8.key.pem -text -noout
openssl asn1parse -in pkcs8.key.pem &>asn1.pkcs8.key.pem
# openssl transformation to der
openssl pkcs8 -topk8 -inform PEM -outform DER -in pkcs8.key.pem -out pkcs8.key.openssl.der -nocrypt
openssl asn1parse -inform DER -in pkcs8.key.openssl.der &>asn1.pkcs8.key.openssl.der
# for check only - the 
head -n-1 pkcs8.key.pem | tail -n+2 | base64 -d >pkcs8.key.unbase64.der
openssl pkey -in pkcs8.key.unbase64.der -text -noout
openssl asn1parse -inform DER -in pkcs8.key.unbase64.der &>asn1.pkcs8.key.unbase64.der

# encrypt pkcs8 key with password 'changeme'
openssl pkcs8 -topk8 -in pkcs8.key.pem -out pkcs8.key.changeme.pem -passout pass:changeme -v2 aes-256-cbc
openssl pkey -in pkcs8.key.changeme.pem -passin pass:changeme -text -noout
openssl asn1parse -in pkcs8.key.changeme.pem &>asn1.pkcs8.key.changeme.pem
# no way to obtain the same der with other encryption
head -n-1 pkcs8.key.changeme.pem | tail -n+2 | base64 -d >pkcs8.key.changeme.unbase64.der
openssl pkey -in pkcs8.key.changeme.unbase64.der -passin pass:changeme -text -noout
openssl asn1parse -inform DER -in pkcs8.key.changeme.unbase64.der &>asn1.pkcs8.key.changeme.unbase64.der

# PKCS1
openssl pkey -in pkcs8.key.pem -out pkcs1.key.pem -traditional
openssl pkey -in pkcs1.key.pem -text -noout
openssl asn1parse -in pkcs1.key.pem &>asn1.pkcs1.key.pem
# standard transformation
openssl pkey -in pkcs1.key.pem -out pkcs1.key.openssl.der -outform DER
openssl pkey -in pkcs1.key.openssl.der -text -noout
openssl asn1parse -inform DER -in pkcs1.key.openssl.der &>asn1.pkcs1.key.openssl.der
# check
head -n-1 pkcs1.key.pem | tail -n+2 | base64 -d >pkcs1.key.unbase64.der
openssl pkey -in pkcs1.key.unbase64.der -text -noout
openssl asn1parse -inform DER -in pkcs1.key.unbase64.der &>asn1.pkcs1.key.unbase64.der

# PKCS12
openssl req -new -x509 -key pkcs8.key.pem -out cert.pem -days $(( ( $(date --date='@2147483647' +%s) - $(date +%s) ) / 86400 )) -subj "/CN=example.com"
openssl x509 -in cert.pem -text -noout
# with password
openssl pkcs12 -export -inkey pkcs8.key.pem -in cert.pem -name "example.com" -out pkcs12.changeme.p12 -passout pass:changeme
openssl pkcs12 -in pkcs12.changeme.p12 -passin pass:changeme -info -nodes
openssl asn1parse -in pkcs12.changeme.p12 -inform DER &>asn1.pkcs12.changeme.p12
# without password - requires console input
openssl pkcs12 -export -inkey pkcs8.key.pem -in cert.pem -name "example.com" -out pkcs12.p12 -passout pass:
openssl pkcs12 -in pkcs12.p12 -info -nodes
openssl asn1parse -in pkcs12.p12 -inform DER &>asn1.pkcs12.p12

# check hash sums for duplicates
md5sum pkcs*pem | sort
md5sum pkcs*der | sort
md5sum asn1* | sort


## 52 bytes of random - max for 512 bit key
#head -c 39 /dev/random | base64 -w0 >random.original
#cp random.original random.test
#md5sum random.test >random.md5
#md5sum -c random.md5
#rm -v random.test
#
#openssl rsa -in pkcs1.key.pem -pubout -out pkcs1.key.public.pem
#openssl pkeyutl -encrypt -pubin -inkey pkcs1.key.public.pem -in random.original -out random.encrypted
#openssl pkeyutl -decrypt -inkey pkcs1.key.pem -in random.encrypted -out random.test
#md5sum -c random.md5
#rm -v random.test
#
