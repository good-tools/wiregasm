gpg-error_VERSION   := 1.46
gpg-error_URL       := https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$(gpg-error_VERSION).tar.bz2
gpg-error_SHA512    := b06223bb2b0f67d3db5d0d9ab116361a0eda175d4667352b5c0941408d37f2b0ba8e507297e480ccebb88cbba9d0a133820b896914b07d264fb3edaac7b8c99d
gpg-error_BUILD     := autotools
gpg-error_CONF      := --disable-nls --disable-languages --disable-tests --disable-doc
gpg-error_MAKE_ARGS := pre_mkheader_cmds=true bin_PROGRAMS=
