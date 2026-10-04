gcrypt_VERSION := 1.10.2
gcrypt_URL     := https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$(gcrypt_VERSION).tar.bz2
gcrypt_SHA512  := 3a850baddfe8ffe8b3e96dc54af3fbb9e1dab204db1f06b9b90b8fbbfb7fb7276260cd1e61ba4dde5a662a2385385007478834e62e95f785d2e3d32652adb29e
gcrypt_BUILD   := autotools
gcrypt_DEPS    := gpg-error
gcrypt_CONF    := \
	--enable-ciphers=aes,des,rfc2268,arcfour,chacha20 \
	--enable-digests=sha1,md5,rmd160,sha256,sha512,blake2 \
	--enable-pubkey-ciphers=dsa,rsa,ecc \
	--disable-doc
