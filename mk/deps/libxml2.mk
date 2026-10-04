libxml2_VERSION := 2.11.9
libxml2_URL     := https://download.gnome.org/sources/libxml2/$(basename $(libxml2_VERSION))/libxml2-$(libxml2_VERSION).tar.xz
libxml2_SHA512  := d5c34ed56525f4c6b61d7055fe4219d7a3337077b4fb27081682e9f8350f1542b4476ac42f2754e590b371a4d9a00921cebf20c10b299371b05b8391e7fa7c33
libxml2_BUILD   := autotools
# library only: no threads (would force pthreads on the module), no network,
# no Python bindings, no dynamic modules
libxml2_CONF    := --without-python --without-threads --without-http --without-ftp \
	--without-modules --without-zlib --without-lzma --without-debug
