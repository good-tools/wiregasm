glib_VERSION := 2.75.0
glib_URL     := https://ftp.gnome.org/pub/gnome/sources/glib/$(basename $(glib_VERSION))/glib-$(glib_VERSION).tar.xz
glib_SHA512  := 0402c063975680ff2385876f521b37aa4cc599d2570eb79976ad2a1b530e47a086d514fe122fd870b4a8f7358f48c926285694d153cc2c32cf6963ed2d5da9d9
glib_BUILD   := meson
glib_DEPS    := pcre ffi
glib_CONF    := \
	--force-fallback-for=gvdb,zlib -Dselinux=disabled -Dxattr=false -Dlibmount=disabled \
	-Dnls=disabled -Dtests=false -Dglib_assert=false -Dglib_checks=false
