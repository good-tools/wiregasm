wireshark_VERSION := 4.6.9
wireshark_URL     := https://www.wireshark.org/download/src/all-versions/wireshark-$(wireshark_VERSION).tar.xz
wireshark_SHA512  := dde86fafc38132c834fb28865f66351aa7cdaccaabc7612731fd418014cf8624471a2a20a5b3a6546bf4b1c397f04d35271bd92a6e4680d63caeabee90cab6aa
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
