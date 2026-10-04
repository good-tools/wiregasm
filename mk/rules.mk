# Generic rules for building a dependency described by mk/deps/<pkg>.mk:
#
#   <pkg>_VERSION, <pkg>_URL, <pkg>_SHA512
#   <pkg>_BUILD      autotools | meson | cmake
#   <pkg>_DEPS       packages that must be built first
#   <pkg>_CONF       extra configure / meson / cmake arguments
#   <pkg>_MAKE_ARGS  extra make arguments (autotools only)
#
# Each package goes through:
#   $(TARBALLS)/<file>       downloaded atomically and checksum-verified
#   $(STAMP)/<pkg>.src       build/src/<pkg>: upstream + overlay/ + patches/ (scripts/patches.mjs)
#   $(STAMP)/<pkg>.built     built out of tree in build/obj/<pkg>, installed into $(PREFIX)

HOST := wasm32-unknown-emscripten

# Resolved through the shell: in the emsdk image /emsdk/node is a directory
# that comes first on PATH, and make's own PATH lookup trips over it (the
# same goes for cmake, hence `env cmake` below).
NODE := $(shell command -v node)
BUILD ?= x86_64-linux

ACLOCAL_AMFLAGS += -I$(PREFIX)/share/aclocal
export ACLOCAL_AMFLAGS

PKG_CONFIG_PATH := $(PREFIX)/lib/pkgconfig
EM_PKG_CONFIG_PATH := $(PKG_CONFIG_PATH)
export PKG_CONFIG_PATH
export EM_PKG_CONFIG_PATH

CFLAGS := $(CFLAGS) -O3
LDFLAGS := $(LDFLAGS) -s TOTAL_MEMORY=128MB

HOSTTOOLS := \
	EM_PKG_CONFIG_PATH="$(EM_PKG_CONFIG_PATH)" \
	CFLAGS="$(CFLAGS)" \
	LDFLAGS="$(LDFLAGS)"

HOSTCONF := --prefix="$(PREFIX)"
HOSTCONF += --datarootdir="$(PREFIX)/share"
HOSTCONF += --includedir="$(PREFIX)/include"
HOSTCONF += --libdir="$(PREFIX)/lib"
HOSTCONF += --program-prefix=""
HOSTCONF += --build="$(BUILD)" --host="$(HOST)" --target="$(HOST)"
HOSTCONF += --enable-static --disable-shared --disable-dependency-tracking
HOSTCONF += PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)"

MESON_ARGS = --default-library static --prefix $(PREFIX) --buildtype release --backend ninja \
	-Dlibdir=lib --cross-file $(CURDIR)/mk/crossfile.meson

# autoreconf rewrites the source tree, so autotools packages build from a copy:
# build/src/<pkg> stays exactly upstream + patches for `make update-patches`.
define build_autotools
rm -rf $(OBJ)/$(1) && mkdir -p $(OBJ)/$(1)/build
cp -a $(SRC)/$(1)/. $(OBJ)/$(1)/src && rm -rf $(OBJ)/$(1)/src/.git
mkdir -p $(PREFIX)/share/aclocal && cd $(OBJ)/$(1)/src && GTKDOCIZE=true autoreconf -fiv $(ACLOCAL_AMFLAGS)
cd $(OBJ)/$(1)/build && $(HOSTTOOLS) emconfigure ../src/configure $(HOSTCONF) $($(1)_CONF)
emmake $(MAKE) -C $(OBJ)/$(1)/build $($(1)_MAKE_ARGS)
emmake $(MAKE) -C $(OBJ)/$(1)/build $($(1)_MAKE_ARGS) install
endef

define build_meson
rm -rf $(OBJ)/$(1)/meson-private
meson setup $(OBJ)/$(1) $(SRC)/$(1) $(MESON_ARGS) $($(1)_CONF)
meson compile -C $(OBJ)/$(1)
meson install -C $(OBJ)/$(1)
endef

define build_cmake
rm -f $(OBJ)/$(1)/CMakeCache.txt
emcmake cmake -G Ninja -S $(SRC)/$(1) -B $(OBJ)/$(1) -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX:STRING=$(PREFIX) -DCMAKE_FIND_ROOT_PATH:STRING=$(PREFIX) $($(1)_CONF)
env cmake --build $(OBJ)/$(1)
env cmake --install $(OBJ)/$(1) --prefix $(PREFIX)
env cmake --install $(OBJ)/$(1) --prefix $(PREFIX) --component Development
if [ -d $(OBJ)/$(1)/staging ]; then cp -rf $(OBJ)/$(1)/staging/* $(PREFIX); fi
endef

define package
$(1)_TARBALL := $(TARBALLS)/$$(notdir $$($(1)_URL))

$$($(1)_TARBALL):
	@mkdir -p $$(@D)
	curl -fsSL -o $$@.tmp -- "$$($(1)_URL)"
	echo "$$($(1)_SHA512)  $$@.tmp" | sha512sum --check --status || { echo "checksum mismatch: $$($(1)_URL)"; rm -f $$@.tmp; exit 1; }
	mv $$@.tmp $$@

$(STAMP)/$(1).src: $$($(1)_TARBALL) $$(wildcard patches/$(1)/*) $$(shell find overlay/$(1) -type f 2>/dev/null) mk/deps/$(1).mk
	$(NODE) scripts/patches.mjs prepare $(1) $$< $(SRC)/$(1)
	@mkdir -p $$(@D) && touch $$@

$(STAMP)/$(1).built: $(STAMP)/$(1).src $$(foreach d,$$($(1)_DEPS),$(STAMP)/$$(d).built) mk/crossfile.meson mk/rules.mk
	@echo "[+] Building $(1)"
	$$(call build_$$($(1)_BUILD),$(1))
	@touch $$@

.PHONY: src-$(1)
src-$(1): $(STAMP)/$(1).src
endef
