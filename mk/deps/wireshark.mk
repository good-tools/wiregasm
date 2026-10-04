wireshark_VERSION := 4.4.5
wireshark_URL     := https://www.wireshark.org/download/src/all-versions/wireshark-$(wireshark_VERSION).tar.xz
wireshark_SHA512  := 09956fadb2ab80df136c6b35a1be2aa72eec20e1f11c94aaaabecff72d450239d09173ef3cc2bcd8c85c194816afb750e1d476538038ff612366a255ae4fece5
wireshark_BUILD   := cmake
wireshark_DEPS    := c-ares gcrypt glib nghttp2
# only libwireshark (epan) is needed; don't build any of the tools
wireshark_CONF    := \
	$(foreach t,wireshark tshark rawshark dumpcap text2pcap mergecap reordercap editcap \
		capinfos captype randpkt dftest dcerpcidl2wrs androiddump sshdump ciscodump \
		dpauxmon randpktdump wifidump etwdump sdjournal udpdump sharkd mmdbresolve,-DBUILD_$(t)=OFF) \
	-DFETCH_lua=ON \
	-DENABLE_CAP=OFF
