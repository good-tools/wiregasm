# Builds the wiregasm wasm module and every dependency it needs.
#
#   make               build built/bin/wiregasm.{js,wasm,data}
#   make docker        same, inside the builder image (no local toolchain needed)
#   make src PKG=x     prepare build/src/x (upstream + overlay/ + patches/) for editing
#   make clean         remove build outputs (keeps downloaded tarballs)
#   make distclean     also remove downloaded tarballs
#
# Dependencies are described in mk/deps/<pkg>.mk; the generic rules live in mk/rules.mk.

EMSDK_VERSION := 3.1.31

TARBALLS := .cache/tarballs
SRC      := build/src
OBJ      := build/obj
STAMP    := build/stamp
PREFIX   := $(CURDIR)/built

.DELETE_ON_ERROR:
.DEFAULT_GOAL := all

include mk/rules.mk
PACKAGES := $(basename $(notdir $(wildcard mk/deps/*.mk)))
include $(wildcard mk/deps/*.mk)
$(foreach p,$(PACKAGES),$(eval $(call package,$(p))))

.PHONY: all deps wiregasm src docker clean distclean

all: wiregasm

deps: $(STAMP)/wireshark.built

# Always rebuilt: it's quick, and meson tracks lib/wiregasm itself.
wiregasm: $(STAMP)/wireshark.built
	@echo "[+] Building Wiregasm"
	rm -rf $(OBJ)/wiregasm/meson-private
	meson setup $(OBJ)/wiregasm lib/wiregasm $(MESON_ARGS)
	meson compile -C $(OBJ)/wiregasm
	meson install -C $(OBJ)/wiregasm

src: guard-PKG $(STAMP)/$(PKG).src

docker:
	docker build -t wiregasm-builder:$(EMSDK_VERSION) --build-arg EMSDK_VERSION=$(EMSDK_VERSION) \
		-f docker/build.Dockerfile docker
	docker run --rm -v "$(CURDIR)":/src -w /src wiregasm-builder:$(EMSDK_VERSION) \
		make -j"$$(nproc)" $(filter-out docker,$(MAKECMDGOALS))

clean:
	rm -rf build built

distclean: clean
	rm -rf .cache

guard-%:
	@if [ -z '$($*)' ]; then echo '$* is not set, e.g. make $(MAKECMDGOALS) $*=wireshark'; exit 1; fi
