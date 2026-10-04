nghttp2_VERSION := 1.61.0
nghttp2_URL     := https://github.com/nghttp2/nghttp2/releases/download/v$(nghttp2_VERSION)/nghttp2-$(nghttp2_VERSION).tar.xz
nghttp2_SHA512  := 01e930d7caf464699505f92b76e2bc8192d168612dc564d2546812c42afea2fb81d552d70e8a5fed35e2bf5deadbec8eda095af94a2484bca41542988afce52a
nghttp2_BUILD   := autotools
nghttp2_CONF    := --enable-lib-only
