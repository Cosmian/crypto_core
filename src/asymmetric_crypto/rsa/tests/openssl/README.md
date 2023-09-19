Files generated using command line openssl to evaluate the compatibility with RSA implementation.

## Random RSA 3072 bit PEM private key

```sh
openssl genrsa -out rsa_3072_bit.key.pkcs8.pem 3072

```

## RSA 3072 bit PEM public key

```sh
openssl rsa -in rsa_3072_bit.key.pkcs8.pem -pubout -out rsa_3072_bit.pub

```

## Random 32 byte secret key

```sh
openssl rand -out 32_byte.key 32

```

## Wrap the secret with CKM_RSA_PKCS_OAEP mechanism

```sh
openssl pkeyutl \
  -encrypt \
  -pubin \
  -inkey rsa_3072_bit.pub.pkcs8.pem \
  -in 32_byte.key \
  -out 32_byte.key.oaep_sha256.enc \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

```
