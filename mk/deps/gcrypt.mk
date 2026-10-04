gcrypt_VERSION := 1.11.0
gcrypt_URL     := https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$(gcrypt_VERSION).tar.bz2
gcrypt_SHA512  := 8e093e69e3c45d30838625ca008e995556f0d5b272de1c003d44ef94633bcc0d0ef5d95e8725eb531bfafb4490ac273488633e0c801200d4666194f86c3e270e
gcrypt_BUILD   := autotools
gcrypt_DEPS    := gpg-error
# sha3: 1.11 references the Keccak code from md.c and kdf.c unconditionally
gcrypt_CONF    := \
	--enable-ciphers=aes,des,rfc2268,arcfour,chacha20 \
	--enable-digests=sha1,md5,rmd160,sha256,sha512,blake2,sha3 \
	--enable-pubkey-ciphers=dsa,rsa,ecc \
	--disable-doc
