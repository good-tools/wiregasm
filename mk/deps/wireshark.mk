wireshark_VERSION := 4.6.10
wireshark_URL     := https://www.wireshark.org/download/src/all-versions/wireshark-$(wireshark_VERSION).tar.xz
wireshark_SHA512  := fd52c764635188bc9ab52ea549537af1b470cf48658221d478ee5ad7fb698bdb0c10008f4c51f2b862e680e8d06c0de62642c3cda98705c6ed40e273ee776190
wireshark_BUILD   := cmake
wireshark_DEPS    := c-ares gcrypt glib libxml2 nghttp2
# only libwireshark (epan) is needed: no tools, no C plugins (not loadable in
# wasm; Lua plugins are separate), and static libraries
# (newer emscripten supports shared libraries, which would otherwise be the default)
wireshark_CONF    := \
	$(foreach t,wireshark tshark rawshark dumpcap text2pcap mergecap reordercap editcap \
		capinfos captype randpkt dftest dcerpcidl2wrs androiddump sshdump ciscodump \
		dpauxmon randpktdump wifidump etwdump sdjournal udpdump sharkd mmdbresolve,-DBUILD_$(t)=OFF) \
	-DFETCH_lua=ON \
	-DENABLE_CAP=OFF \
	-DBUILD_SHARED_LIBS=OFF \
	-DENABLE_PLUGINS=OFF
