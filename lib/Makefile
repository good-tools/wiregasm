# Makefile from VLC contrib was used as a reference
# https://code.videolan.org/videolan/vlc/-/blob/master/contrib/src/main.mak

all: .wiregasm

TARBALLS := tarballs
PATCHES := ../patches
PREFIX := ../built
PREFIX := $(abspath $(PREFIX))
VPATH := $(TARBALLS)
BUILD ?= x86_64-linux
HOST := wasm32-unknown-emscripten

ACLOCAL_AMFLAGS += -I$(PREFIX)/share/aclocal
export ACLOCAL_AMFLAGS

download = curl -sSL -- "$(1)" > "$@"
checksum = echo "$(1) $(2)" | sha512sum --check --status

EXTRACT_DIR = $(patsubst %.tar,%,$(basename $(notdir $<)))
APPLY = (cd $(EXTRACT_DIR) && patch -fp1) <
MOVE = mv $(EXTRACT_DIR) $@ && touch $@
CLEANUP = rm -rf $@
BUILD_DIR = $</wg_build
AUTORECONF = GTKDOCIZE=true autoreconf
RECONF = mkdir -p -- $(PREFIX)/share/aclocal && cd $< && $(AUTORECONF) -fiv $(ACLOCAL_AMFLAGS)
CMAKECLEAN = rm -f $(BUILD_DIR)/CMakeCache.txt

PKG_CONFIG_PATH := $(PREFIX)/lib/pkgconfig
EM_PKG_CONFIG_PATH := $(PKG_CONFIG_PATH)
export PKG_CONFIG_PATH
export EM_PKG_CONFIG_PATH

.PHONY: GUARD

guard-%: GUARD
	@ if [ -z '${${*}}' ]; then echo 'Environment variable $* not set.' && exit 1; fi

# common
HOSTCONF := --prefix="$(PREFIX)"
HOSTCONF += --datarootdir="$(PREFIX)/share"
HOSTCONF += --includedir="$(PREFIX)/include"
HOSTCONF += --libdir="$(PREFIX)/lib"
HOSTCONF += --program-prefix=""
HOSTCONF += --build="$(BUILD)" --host="$(HOST)" --target="$(HOST)"
HOSTCONF += --enable-static --disable-shared --disable-dependency-tracking
HOSTCONF += PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)"

EXTRA_LDFLAGS := -s TOTAL_MEMORY=128MB
EXTRA_CFLAGS := -O3
CFLAGS := $(CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

HOSTTOOLS := \
	EM_PKG_CONFIG_PATH="$(EM_PKG_CONFIG_PATH)" \
	CFLAGS="$(CFLAGS)" \
	LDFLAGS="$(LDFLAGS)"

# meson
MESON_CLEAN = rm -rf $(BUILD_DIR)/meson-private
MESON_SETUP = meson setup $(BUILD_DIR) $< --default-library static --prefix $(PREFIX) --buildtype release --backend ninja -Dlibdir=lib --cross-file $(abspath crossfile.meson)
MESON_BUILD = meson compile -C $(BUILD_DIR) && meson install -C $(BUILD_DIR)

mostlyclean:
	rm -rf c-ares ffi gcrypt glib gpg-error pcre nghttp2 wireshark
	rm -rf .c-ares .ffi .gcrypt .glib .gpg-error .pcre .nghttp2 .wireshark
	rm -rf .sum-*

clean: mostlyclean
	rm -rf $(TARBALLS)/*.*

#
# CARES
#
CARES_VERSION := 1.15.0
CARES_URL := https://github.com/c-ares/c-ares/releases/download/cares-$(subst .,_,$(CARES_VERSION))/c-ares-$(CARES_VERSION).tar.gz
CARES_CHECKSUM := a1de6c5e7e1a6a13c926aae690e83d5caa51e7313d63da1cf2af6bc757c41d585aad5466bc3ba7b7f7793cb1748fa589f40972b196728851c8b059cfc8c3be50

$(TARBALLS)/c-ares-$(CARES_VERSION).tar.gz:
	$(call download,$(CARES_URL))

.sum-c-ares: c-ares-$(CARES_VERSION).tar.gz
	$(call checksum,$(CARES_CHECKSUM),$<)
	touch $@

c-ares: c-ares-$(CARES_VERSION).tar.gz .sum-c-ares
	$(CLEANUP)
	tar xzfo $<
	$(MOVE)

.c-ares: c-ares
	echo "[+] Building c-ares"
	$(RECONF)
	mkdir -p $(BUILD_DIR) && rm -f $(BUILD_DIR)/config.status && test ! -f $</config.status || $(MAKE) -C $< distclean
	cd $(BUILD_DIR) && $(HOSTTOOLS) emconfigure ../configure $(HOSTCONF)
	emmake make -C $(BUILD_DIR)
	emmake make -C $(BUILD_DIR) install
	touch $@

#
# FFI
#
FFI_VERSION := 3.4.4
FFI_URL := https://github.com/libffi/libffi/releases/download/v$(FFI_VERSION)/libffi-$(FFI_VERSION).tar.gz
FFI_CHECKSUM := 88680aeb0fa0dc0319e5cd2ba45b4b5a340bc9b4bcf20b1e0613b39cd898f177a3863aa94034d8e23a7f6f44d858a53dcd36d1bb8dee13b751ef814224061889

$(TARBALLS)/libffi-$(FFI_VERSION).tar.gz:
	$(call download,$(FFI_URL))

.sum-ffi: libffi-$(FFI_VERSION).tar.gz
	$(call checksum,$(FFI_CHECKSUM),$<)
	touch $@

ffi: libffi-$(FFI_VERSION).tar.gz .sum-ffi
	$(CLEANUP)
	tar xzfo $<
	$(APPLY) $(PATCHES)/ffi/emscripten.3.4.4.patch
	$(MOVE)

.ffi: ffi
	echo "[+] Building ffi"
	$(RECONF)
	mkdir -p $(BUILD_DIR) && rm -f $(BUILD_DIR)/config.status && test ! -f $</config.status || $(MAKE) -C $< distclean
	cd $(BUILD_DIR) && $(HOSTTOOLS) emconfigure ../configure $(HOSTCONF)
	emmake make -C $(BUILD_DIR)
	emmake make -C $(BUILD_DIR) install
	touch $@

#
# PCRE
#
# XXX: the glib project can also built pcre
#
PCRE_VERSION := 10.42
PCRE_URL := https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$(PCRE_VERSION)/pcre2-$(PCRE_VERSION).tar.bz2
PCRE_CHECKSUM := 72fbde87fecec3aa4b47225dd919ea1d55e97f2cbcf02aba26e5a0d3b1ffb58c25a80a9ef069eb99f9cf4e41ba9604ad06a7ec159870e1e875d86820e12256d3

$(TARBALLS)/pcre2-$(PCRE_VERSION).tar.bz2:
	$(call download,$(PCRE_URL))

.sum-pcre: pcre2-$(PCRE_VERSION).tar.bz2
	$(call checksum,$(PCRE_CHECKSUM),$<)
	touch $@

pcre: pcre2-$(PCRE_VERSION).tar.bz2 .sum-pcre
	$(CLEANUP)
	tar xjfo $<
	$(MOVE)

.pcre: pcre
	echo "[+] Building pcre"
	$(RECONF)
	mkdir -p $(BUILD_DIR) && rm -f $(BUILD_DIR)/config.status && test ! -f $</config.status || $(MAKE) -C $< distclean
	cd $(BUILD_DIR) && $(HOSTTOOLS) emconfigure ../configure $(HOSTCONF)
	emmake make -C $(BUILD_DIR)
	emmake make -C $(BUILD_DIR) install
	touch $@

#
# GPG-ERROR
#
GPGERROR_VERSION := 1.46
GPGERROR_URL := https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$(GPGERROR_VERSION).tar.bz2
GPGERROR_CHECKSUM := b06223bb2b0f67d3db5d0d9ab116361a0eda175d4667352b5c0941408d37f2b0ba8e507297e480ccebb88cbba9d0a133820b896914b07d264fb3edaac7b8c99d
GPGERROR_CONF := \
	--disable-nls \
	--disable-languages \
	--disable-tests \
	--disable-doc

$(TARBALLS)/libgpg-error-$(GPGERROR_VERSION).tar.bz2:
	$(call download,$(GPGERROR_URL))

.sum-gpg-error: libgpg-error-$(GPGERROR_VERSION).tar.bz2
	$(call checksum,$(GPGERROR_CHECKSUM),$<)
	touch $@

gpg-error: libgpg-error-$(GPGERROR_VERSION).tar.bz2 .sum-gpg-error
	$(CLEANUP)
	tar xjfo $<
	cp -f -- "$(PATCHES)/gpg-error/lock-obj-pub.emscripten.h" \
		"$(EXTRACT_DIR)/src/syscfg/lock-obj-pub.emscripten.h"
	$(MOVE)

.gpg-error: gpg-error
	echo "[+] Building gpg-error"
	$(RECONF)
	mkdir -p $(BUILD_DIR) && rm -f $(BUILD_DIR)/config.status && test ! -f $</config.status || $(MAKE) -C $< distclean
	cd $(BUILD_DIR) && $(HOSTTOOLS) emconfigure ../configure $(HOSTCONF) $(GPGERROR_CONF)
	emmake make -C $(BUILD_DIR) pre_mkheader_cmds=true bin_PROGRAMS=
	emmake make -C $(BUILD_DIR) pre_mkheader_cmds=true bin_PROGRAMS= install
	touch $@

#
# GCRYPT
#
GCRYPT_VERSION := 1.10.1
GCRYPT_URL := http://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$(GCRYPT_VERSION).tar.bz2
GCRYPT_CHECKSUM := e5ca7966624fff16c3013795836a2c4377f0193dbb4ac5ad2b79654b1fa8992e17d83816569a402212dc8367a7980d4141f5d6ac282bae6b9f02186365b61f13
GCRYPT_CONF = \
	--enable-ciphers=aes,des,rfc2268,arcfour,chacha20 \
	--enable-digests=sha1,md5,rmd160,sha256,sha512,blake2 \
	--enable-pubkey-ciphers=dsa,rsa,ecc \
	--disable-doc

$(TARBALLS)/libgcrypt-$(GCRYPT_VERSION).tar.bz2:
	$(call download,$(GCRYPT_URL))

.sum-gcrypt: libgcrypt-$(GCRYPT_VERSION).tar.bz2
	$(call checksum,$(GCRYPT_CHECKSUM),$<)
	touch $@

gcrypt: libgcrypt-$(GCRYPT_VERSION).tar.bz2 .sum-gcrypt
	$(CLEANUP)
	tar xjfo $<
	$(MOVE)

.gcrypt: gcrypt .gpg-error
	echo "[+] Building Gcrypt"
	$(RECONF)
	mkdir -p $(BUILD_DIR) && rm -f $(BUILD_DIR)/config.status && test ! -f $</config.status || $(MAKE) -C $< distclean
	cd $(BUILD_DIR) && $(HOSTTOOLS) emconfigure ../configure $(HOSTCONF) $(GCRYPT_CONF)
	emmake make -C $(BUILD_DIR)
	emmake make -C $(BUILD_DIR) install
	touch $@

#
# GLIB
#
GLIB_VERSION := 2.75
GLIB_MINOR_VERSION := $(GLIB_VERSION).0
GLIB_URL := https://ftp.gnome.org/pub/gnome/sources/glib/$(GLIB_VERSION)/glib-$(GLIB_MINOR_VERSION).tar.xz
GLIB_CHECKSUM := 0402c063975680ff2385876f521b37aa4cc599d2570eb79976ad2a1b530e47a086d514fe122fd870b4a8f7358f48c926285694d153cc2c32cf6963ed2d5da9d9

$(TARBALLS)/glib-$(GLIB_MINOR_VERSION).tar.xz:
	$(call download,$(GLIB_URL))

.sum-glib: glib-$(GLIB_MINOR_VERSION).tar.xz
	$(call checksum,$(GLIB_CHECKSUM),$<)
	touch $@

glib: glib-$(GLIB_MINOR_VERSION).tar.xz .sum-glib
	$(CLEANUP)
	tar xJfo $<
	$(APPLY) $(PATCHES)/glib/emscripten.2.75.0.patch
	$(MOVE)

.glib: glib .pcre .ffi crossfile.meson
	echo "[+] Building Glib"
	$(MESON_CLEAN)
	$(MESON_SETUP) --force-fallback-for=gvdb,zlib -Dselinux=disabled -Dxattr=false -Dlibmount=disabled \
	 -Dnls=disabled -Dtests=false -Dglib_assert=false -Dglib_checks=false
	+$(MESON_BUILD)
	touch $@

NGHTTP2_VERSION := 1.61.0
NGHTTP2_URL := https://github.com/nghttp2/nghttp2/releases/download/v$(NGHTTP2_VERSION)/nghttp2-$(NGHTTP2_VERSION).tar.xz
NGHTTP2_CHECKSUM := 01e930d7caf464699505f92b76e2bc8192d168612dc564d2546812c42afea2fb81d552d70e8a5fed35e2bf5deadbec8eda095af94a2484bca41542988afce52a
NGHTTP2_CONF := \
	--enable-lib-only

$(TARBALLS)/nghttp2-$(NGHTTP2_VERSION).tar.xz:
	$(call download,$(NGHTTP2_URL))

.sum-nghttp2: nghttp2-$(NGHTTP2_VERSION).tar.xz
	$(call checksum,$(NGHTTP2_CHECKSUM),$<)
	touch $@

nghttp2: nghttp2-$(NGHTTP2_VERSION).tar.xz .sum-nghttp2
	$(CLEANUP)
	tar xJfo $<
	$(MOVE)

.nghttp2: nghttp2
	echo "[+] Building nghttp2"
	$(RECONF)
	mkdir -p $(BUILD_DIR) && rm -f $(BUILD_DIR)/config.status && test ! -f $</config.status || $(MAKE) -C $< distclean
	cd $(BUILD_DIR) && $(HOSTTOOLS) emconfigure ../configure $(HOSTCONF) $(NGHTTP2_CONF)
	emmake make -C $(BUILD_DIR)
	emmake make -C $(BUILD_DIR) install
	touch $@

#
# Wireshark (epan)
#
WIRESHARK_VERSION := 4.2.5
WIRESHARK_URL := https://www.wireshark.org/download/src/all-versions/wireshark-$(WIRESHARK_VERSION).tar.xz
WIRESHARK_CHECKSUM := 92a8fb08af5a1da30ca469fa45bd982638069907d289fa716068ac71141b7d9726ca0b01adc2910da4c928db23760da75a1c6a7c2eb795ac66ba003a90abb87b
# do not build any tools, we're only interested in libwireshark (epan)
WIRESHARK_CONF = \
	-DBUILD_wireshark=OFF \
	-DBUILD_tshark=OFF \
	-DBUILD_rawshark=OFF \
	-DBUILD_dumpcap=OFF \
	-DBUILD_text2pcap=OFF \
	-DBUILD_mergecap=OFF \
	-DBUILD_reordercap=OFF \
	-DBUILD_editcap=OFF \
	-DBUILD_capinfos=OFF \
	-DBUILD_captype=OFF \
	-DBUILD_randpkt=OFF \
	-DBUILD_dftest=OFF \
	-DBUILD_dcerpcidl2wrs=OFF \
	-DBUILD_androiddump=OFF \
	-DBUILD_sshdump=OFF \
	-DBUILD_ciscodump=OFF \
	-DBUILD_dpauxmon=OFF \
	-DBUILD_randpktdump=OFF \
	-DBUILD_wifidump=OFF \
	-DBUILD_etwdump=OFF \
	-DBUILD_sdjournal=OFF \
	-DBUILD_udpdump=OFF \
	-DBUILD_sharkd=OFF \
	-DBUILD_mmdbresolve=OFF \
	-DFETCH_lua=ON \
	-DENABLE_CAP=OFF

$(TARBALLS)/wireshark-$(WIRESHARK_VERSION).tar.xz:
	$(call download,$(WIRESHARK_URL))

.sum-wireshark: wireshark-$(WIRESHARK_VERSION).tar.xz
	$(call checksum,$(WIRESHARK_CHECKSUM),$<)
	touch $@

wireshark: wireshark-$(WIRESHARK_VERSION).tar.xz .sum-wireshark
	$(CLEANUP)
	tar xJfo $<
	$(APPLY) $(PATCHES)/wireshark/0001-dont-build-radiotap-lemon.patch
	# $(APPLY) $(PATCHES)/wireshark/0002-fix-cpu-name-unknown.patch
	$(APPLY) $(PATCHES)/wireshark/0003-disable-snort-emscripten.patch
	$(APPLY) $(PATCHES)/wireshark/0004-export-wireshark-common.patch
	$(APPLY) $(PATCHES)/wireshark/0005-force-data-dir.patch
	$(APPLY) $(PATCHES)/wireshark/0006-threadless-registration.patch
	$(APPLY) $(PATCHES)/wireshark/0007-export-lrexlib.patch
	$(APPLY) $(PATCHES)/wireshark/0008-export-wslua-headers.patch
	$(MOVE)

.wireshark: wireshark .c-ares .gcrypt .glib .nghttp2
	echo "[+] Building Wireshark"
	$(CMAKECLEAN)
	emcmake cmake -G Ninja -S $< -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:STRING=$(PREFIX) -DCMAKE_FIND_ROOT_PATH:STRING=$(PREFIX) $(WIRESHARK_CONF)
	env cmake --build $(BUILD_DIR)
	env cmake --install $(BUILD_DIR) --prefix $(PREFIX) --component Development
	cp -rf $(BUILD_DIR)/staging/* $(PREFIX) # copy artifacts from the staging directory
	touch $@

#
# Wiregasm Lib
#
.wiregasm: wiregasm .wireshark crossfile.meson
	echo "[+] Building Wiregasm"
	$(MESON_CLEAN)
	$(MESON_SETUP)
	+$(MESON_BUILD)
