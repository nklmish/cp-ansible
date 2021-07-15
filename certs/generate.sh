#!/bin/bash -e
generate_cacertificate () {
    _NAME=$1
    _SUBJ=$2
    [ ! -f $_NAME.key ] \
    && openssl genrsa \
    -des3 \
    -out $_NAME.key \
    -passout pass:$CAPASS \
    4096 \
    && rm -f $_NAME.crt \
    && echo "$_NAME.key generated"

    [ ! -f $_NAME.crt ] \
    && openssl req -x509 \
    -new \
    -key $_NAME.key \
    -passin pass:$CAPASS \
    -days 1024 \
    -sha256 \
    -subj "$_SUBJ" \
    -out $_NAME.crt \
    && rm -f $_NAME.pem \
    && echo "$_NAME.crt generated"

    [ ! -f $_NAME.pem ] \
    && cp $_NAME.crt $_NAME.pem \
    && echo "$_NAME.pem generated"

    return 0
}

generate_certificate () {

    _NAME=$1
    _SUBJ=$2
    _EXT=$3
    _CA=${4:-ca}

    [ ! -f $_NAME.key ] \
    && openssl genrsa \
    -des3 \
    -out $_NAME.key \
    -passout pass:$CERTPASS \
    2048 \
    && rm -f $_NAME.csr \
    && echo "$_NAME.key generated"

    [ ! -f $_NAME.csr ] \
    && openssl req \
    -new \
    -key $_NAME.key \
    -passin pass:$CERTPASS \
    -sha256 \
    -subj "$_SUBJ" \
    -out $_NAME.csr \
    && rm -f $_NAME.crt \
    && echo "$_NAME.csr generated"

    [ ! -f $_NAME.crt ] \
    && openssl x509 \
    -req \
    -CA ${_CA}.crt \
    -CAkey ${_CA}.key \
    -CAcreateserial \
    -in $_NAME.csr \
    -out $_NAME.crt \
    -days 365 \
    -sha256  \
    -passin pass:$CAPASS \
    -extfile <(printf "$_EXT") \
    && rm -f $_NAME.pem \
    && echo "$_NAME.crt generated"

    # to include the full certification chain
    [ ! -f $_NAME.pem ] \
    && cat $_NAME.crt ${_CA}.pem > $_NAME.pem \
    && rm -f $_NAME.p12 \
    && echo "$_NAME.pem generated"

    [ ! -f $_NAME.p12 ] \
    && openssl pkcs12 \
    -export \
    -chain \
    -CAfile ${_CA}.pem \
    -name $_NAME \
    -in $_NAME.crt \
    -inkey $_NAME.key \
    -passin pass:$CERTPASS \
    -passout pass:$CERTPASS \
    -out $_NAME.p12 \
    && rm -f $_NAME.jks \
    && echo "$_NAME.p12 generated"

    [ ! -f $_NAME.jks ] \
    && keytool -importkeystore -v \
    -srckeystore $_NAME.p12 \
    -srcstoretype PKCS12 \
    -srcstorepass $CERTPASS \
    -destkeystore $_NAME.jks \
    -deststoretype JKS \
    -deststorepass $CERTPASS \
    && echo "$_NAME.jks generated"

    return 0

}

CAPASS=confluent
CERTPASS=abcdefgh

# Root CA certificate
CAPASS=q6KasGX35jR5 \
generate_cacertificate \
  rootca \
  "/C=DE/O=Siemens/OU=demo-org-unit/CN=Root CA"

[ ! -f rootca.p12 ] \
&& openssl pkcs12 \
-export \
-nokeys \
-in rootca.pem \
-name rootca \
-passout pass:changeit \
-out rootca.p12 \
&& echo "rootca.p12 generated"

[ ! -f rootca.jks ] \
&& keytool -importcert -v \
-noprompt \
-file rootca.crt \
-alias ca \
-destkeystore rootca.jks \
-deststoretype JKS \
-deststorepass abcdefgh \
&& echo "rootca.jks generated"

[ ! -f ca.p12 ] \
&& openssl pkcs12 \
-export \
-nokeys \
-in sslca.pem \
-name sslca \
-name rootca \
-passout pass:abcdefgh \
-out ca.p12 \
&& echo "ca.p12 generated"

[ ! -f ca.jks ] \
&& keytool -importcert -v \
-noprompt \
-file rootca.pem \
-alias rootca \
-destkeystore ca.jks \
-deststoretype JKS \
-deststorepass abcdefgh \
&& keytool -importcert -v \
-noprompt \
-file sslca.pem \
-alias sslca \
-destkeystore ca.jks \
-deststoretype JKS \
-deststorepass abcdefgh \
&& echo "ca.jks generated"

# Intermediate SSL CA certificate
CAPASS=q6KasGX35jR5 \
CERTPASS=jFPcC4bGD4e7 \
generate_certificate \
  sslca \
  "/C=DE/O=Siemens/OU=demo-org-unit/CN=SSL CA" \
  "basicConstraints=CA:TRUE\nkeyUsage=digitalSignature,keyCertSign" \
  rootca

CAPASS=jFPcC4bGD4e7
# for mTLS add clientAuth to extendedKeyUsage
#zookeeper certificates
for i in {0..4} ; do
  generate_certificate \
    zookeeper-${i} \
    "/C=DE/O=Siemens/OU=demo-org-unit/CN=zookeeper-${i}" \
    "subjectAltName=DNS:zookeeper-${i},DNS:zookeeper-${i}.demodomain\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" \
    sslca
done

#Broker
for i in {0..2} ; do
  generate_certificate \
    broker-${i} \
    "/C=DE/O=Siemens/OU=demo-org-unit/CN=broker-${i}" \
    "subjectAltName=DNS:broker-${i},DNS:broker-${i}.demodomain,DNS:kafka.demo.siemens.kafka.confluent.io,DNS:b-${i}.kafka.demo.siemens.kafka.confluent.io\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" \
    sslca
done

#SR
for i in {0..1} ; do
  generate_certificate \
    registry-${i} \
    "/C=DE/O=Siemens/OU=demo-org-unit/CN=registry-${i}" \
    "subjectAltName=DNS:registry-${i},DNS:registry-${i}.demodomain,DNS:registry.demo.siemens.kafka.confluent.io\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" \
    sslca
done

#C3
for i in {0..0} ; do
  generate_certificate \
    c3-${i} \
    "/C=DE/O=Siemens/OU=demo-org-unit/CN=c3-${i}" \
    "subjectAltName=DNS:c3-${i},DNS:c3-${i}.demodomain,DNS:c3.demo.siemens.kafka.confluent.io\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" \
    sslca
done

#Connect
for i in {0..1} ; do
  generate_certificate \
    connect-${i} \
    "/C=DE/O=Siemens/OU=demo-org-unit/CN=connect-${i}" \
    "subjectAltName=DNS:connect-${i},DNS:connect-${i}.demodomain,DNS:connect.demo.siemens.kafka.confluent.io\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" \
    sslca
done

#Connect
for i in {0..1} ; do
  generate_certificate \
    replicator-${i} \
    "/C=DE/O=Siemens/OU=demo-org-unit/CN=replicator-${i}" \
    "subjectAltName=DNS:replicator-${i},DNS:replicator-${i}.demodomain,DNS:replicator.demo.siemens.kafka.confluent.io\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" \
    sslca
done