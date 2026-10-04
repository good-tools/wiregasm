gpg-error_VERSION   := 1.47
gpg-error_URL       := https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$(gpg-error_VERSION).tar.bz2
gpg-error_SHA512    := bbb4b15dae75856ee5b1253568674b56ad155524ae29a075cb5b0a7e74c4af685131775c3ea2226fff2f84ef80855e77aa661645d002b490a795c7ae57b66a30
gpg-error_BUILD     := autotools
gpg-error_CONF      := --disable-nls --disable-languages --disable-tests --disable-doc
gpg-error_MAKE_ARGS := pre_mkheader_cmds=true bin_PROGRAMS=
