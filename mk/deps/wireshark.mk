# 5.0.0 isn't tagged yet: build the release-5.0 branch at a fixed commit, from
# GitLab's archive of it. Go back to the release tarball once 5.0.0 is out.
wireshark_VERSION := 5.0.0
wireshark_COMMIT  := 6e6de0a7ed3689401a5297799c297548126483ed
wireshark_URL     := https://gitlab.com/wireshark/wireshark/-/archive/$(wireshark_COMMIT)/wireshark-$(wireshark_COMMIT).tar.gz
wireshark_SHA512  := 721879d90aa0de32131731d886b5d4af714c5096f03fc6becab85fa26dd4dfb0bad599d6e218ae00a74ae93077b1109b3580028c2bc79db2d2e20f8f0a7af820
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
