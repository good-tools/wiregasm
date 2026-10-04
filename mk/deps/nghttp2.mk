nghttp2_VERSION := 1.62.1
nghttp2_URL     := https://github.com/nghttp2/nghttp2/releases/download/v$(nghttp2_VERSION)/nghttp2-$(nghttp2_VERSION).tar.xz
nghttp2_SHA512  := d5d6b068712e9b467547b0e5380465b8540317134f3f26c2b0c60eb9c604be2f37b4517a98b371d5f5fb668ce2ee35603ddd944224f11e96382aa541a6a17b4c
nghttp2_BUILD   := autotools
nghttp2_CONF    := --enable-lib-only
