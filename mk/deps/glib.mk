glib_VERSION := 2.80.3
glib_URL     := https://ftp.gnome.org/pub/gnome/sources/glib/$(basename $(glib_VERSION))/glib-$(glib_VERSION).tar.xz
glib_SHA512  := b9c40e912c386192538ebe91b8aefca0ef00c9536b83604826ec9d3f1b963837e3330edd25ab6e11b8d8e3a475b2ea0938753a6ea8f657c8fcc93c3288b600c5
glib_BUILD   := meson
glib_DEPS    := pcre ffi
glib_CONF    := \
	--force-fallback-for=gvdb,zlib -Dselinux=disabled -Dxattr=false -Dlibmount=disabled \
	-Dnls=disabled -Dtests=false -Dglib_assert=false -Dglib_checks=false
