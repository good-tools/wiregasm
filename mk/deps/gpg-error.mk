gpg-error_VERSION   := 1.51
gpg-error_URL       := https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$(gpg-error_VERSION).tar.bz2
gpg-error_SHA512    := 4489f615c6a0389577a7d1fd7d3917517bb2fe032abd9a6d87dfdbd165dabcf53f8780645934020bf27517b67a064297475888d5b368176cf06bc22f1e735e2b
gpg-error_BUILD     := autotools
gpg-error_CONF      := --disable-nls --disable-languages --disable-tests --disable-doc
gpg-error_MAKE_ARGS := pre_mkheader_cmds=true bin_PROGRAMS=
