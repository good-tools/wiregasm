c-ares_VERSION := 1.31.0
c-ares_URL     := https://github.com/c-ares/c-ares/releases/download/v$(c-ares_VERSION)/c-ares-$(c-ares_VERSION).tar.gz
c-ares_SHA512  := 571d2555b4aaf3bf9cd7b5c89be8448ca26fe0ea1f3d664b07a01b42d28af4f5412b30485ef01d4bacc4e08de487dc6eeda98acf212a6a08edec6805f17210cc
c-ares_BUILD   := autotools
# emscripten declares getrandom() but doesn't implement it; and keep the
# library single-threaded (threads would force pthreads on the whole module)
c-ares_CONF    := --disable-cares-threads --disable-tests ac_cv_have_decl_getrandom=no
