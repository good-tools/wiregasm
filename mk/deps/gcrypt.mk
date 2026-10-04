gcrypt_VERSION := 1.10.1
gcrypt_URL     := https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$(gcrypt_VERSION).tar.bz2
gcrypt_SHA512  := e5ca7966624fff16c3013795836a2c4377f0193dbb4ac5ad2b79654b1fa8992e17d83816569a402212dc8367a7980d4141f5d6ac282bae6b9f02186365b61f13
gcrypt_BUILD   := autotools
gcrypt_DEPS    := gpg-error
gcrypt_CONF    := \
	--enable-ciphers=aes,des,rfc2268,arcfour,chacha20 \
	--enable-digests=sha1,md5,rmd160,sha256,sha512,blake2 \
	--enable-pubkey-ciphers=dsa,rsa,ecc \
	--disable-doc
