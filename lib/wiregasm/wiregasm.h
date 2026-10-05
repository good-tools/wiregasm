// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WIREGASM_H
#define WIREGASM_H

#include <glib.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <wireshark/cfile.h>

struct ProtoTree {
  std::string label;
  std::string filter;
  std::string severity;
  std::string type;
  std::string url;
  unsigned int fnum;
  int start;
  int length;
  int data_source_idx;
  std::vector<ProtoTree> tree;
};

struct FollowPayload {
  int number;
  std::string data;
  unsigned int server;
};

struct Follow {
  std::string shost;
  std::string sport;
  unsigned int sbytes;
  std::string chost;
  std::string cport;
  unsigned int cbytes;
  std::vector<FollowPayload> payloads;
};

struct DataSource {
  std::string name;
  std::string data;
};

struct CompleteField {
  std::string field;
  int type;
  std::string name;
};

struct Frame {
  int number;
  std::vector<std::string> comments;
  std::vector<DataSource> data_sources;
  std::vector<ProtoTree> tree;
  std::vector<std::vector<std::string>> follow;
};

struct FrameMeta {
  int number;
  bool comments;
  bool ignored;
  bool marked;
  unsigned int bg;
  unsigned int fg;
  std::vector<std::string> columns;
};

struct Summary {
  std::string filename;
  std::string file_type; // wtap_file_type_subtype_description
  unsigned int file_length;
  std::string file_encap_type; // wtap_encap_description
  unsigned int packet_count;
  double start_time;
  double stop_time;
  double elapsed_time;
};

struct LoadResponse {
  int code;
  std::string error;
  Summary summary;
};

struct FramesResponse {
  std::vector<FrameMeta> frames;
  unsigned int matched;
};

struct CheckFilterResponse {
  bool ok;
  std::string error;
};

struct IoGraph {
  std::vector<float> items;
};

struct IoGraphResult {
  std::string error;
  std::vector<IoGraph> iograph;
};

// base struct
struct TapValue {
  std::string tap;
  std::string type;
  std::string proto;
  virtual ~TapValue() = default;
};

struct GeoIp {
  std::string country;
  std::string country_iso;
  std::string city;
  std::string as_org;
  uint32_t as;
  double lat;
  double lon;
};

struct Conversation {
  std::string saddr;        // source address
  std::string daddr;        // destination address
  std::string sport;        // source port
  std::string dport;        // destination port
  int conv_id;              // conversation id
  unsigned txf;             // number of transmitted frames
  unsigned txb;             // number of transmitted bytes
  unsigned rxf;             // number of received frames
  unsigned rxb;             // number of received bytes
  unsigned tx_frames_total; // number of transmitted frames total
  unsigned rx_frames_total; // number of received frames total
  unsigned tx_bytes_total;  // number of transmitted bytes total
  unsigned rx_bytes_total;  // number of received bytes total
  double start;             // relative start time for the conversation
  double stop;              // relative stop time for the conversation
  double start_abs_time;    // absolute start time for the conversation
  bool filtered;            // whether the entry contains only filtered data
  std::string filter;       // filter std::string
};

struct Host {
  std::string host;         // host address
  std::string port;         // host port
  unsigned txf;             // number of transmitted frames
  unsigned txb;             // number of transmitted bytes
  unsigned rxf;             // number of received frames
  unsigned rxb;             // number of received bytes
  unsigned tx_frames_total; // number of transmitted frames total
  unsigned rx_frames_total; // number of received frames total
  unsigned tx_bytes_total;  // number of transmitted bytes total
  unsigned rx_bytes_total;  // number of received bytes total
  bool filtered;            // whether the entry contains only filtered data
  std::string filter;       // filter std::string
};

struct ExportObject {
  unsigned pkt;
  std::string hostname;
  std::string type;
  std::string filename;
  std::string _download;
  size_t len;
};

// derived structs
struct TapConvResponse : TapValue {
  bool geoip;
  std::vector<Conversation> convs;
  std::vector<Host> hosts;
};

struct TapExportObject : TapValue {
  std::vector<ExportObject> objects;
};

// response struct
struct TapResponse {
  std::vector<std::shared_ptr<TapValue>> taps;
  std::string error;
};

using MapInput = std::map<std::string, std::string>;

struct PrefEnum {
  std::string name;
  std::string description;
  int value;
  bool selected;
};

struct PrefData {
  std::string name;
  std::string title;
  std::string description;

  int type;

  // TODO: make these optional, emscripten now supports optional fields
  uint uint_value;
  uint uint_base_value;
  bool bool_value;
  std::string string_value;
  std::vector<PrefEnum> enum_value;
  std::string range_value;
};

struct SetPrefResponse {
  int code;
  std::string error;
};

struct PrefResponse {
  int code;
  PrefData data;
};

struct PrefModule {
  std::string name;
  std::string title;
  std::string description;
  std::vector<PrefModule> submodules;
  bool use_gui;
};

struct FilterCompletionResponse {
  std::vector<CompleteField> fields;
};

struct Download {
  std::string file;
  std::string mime;
  std::string data;
};

struct DownloadResponse {
  std::string error;
  Download download;
};

// Protocol info struct for listing all protocols
struct ProtocolInfo {
  int id;                  // protocol ID
  std::string name;        // protocol filter name (e.g., "tcp")
  std::string long_name;   // protocol long name (e.g., "Transmission Control Protocol")
  bool enabled;            // whether protocol is currently enabled
  bool enabled_by_default; // whether protocol is enabled by default
  bool can_toggle;         // whether protocol can be toggled (some can't)
};

// Heuristic dissector info struct for listing all heuristic dissectors
struct HeuristicInfo {
  std::string short_name;    // unique short name (e.g., "mac_nr_udp")
  std::string display_name;  // display name for UI
  std::string list_name;     // parent dissector table name (e.g., "udp")
  std::string protocol_name; // associated protocol name
  int protocol_id;           // protocol ID this heuristic belongs to
  bool enabled;              // whether heuristic is currently enabled
  bool enabled_by_default;   // whether heuristic is enabled by default
};

// Unified enabled item for building a hierarchical UI like Wireshark's Enabled Protocols dialog
// Can represent either a protocol or a heuristic dissector
struct EnabledProtocolItem {
  // Common fields
  std::string name;        // display name (short_name for protocols, display_name for heuristics)
  std::string description; // long description
  bool enabled;            // whether currently enabled
  bool enabled_by_default; // whether enabled by default
  bool can_toggle;         // whether can be toggled

  // Type identification
  bool is_heuristic; // true if this is a heuristic, false if protocol

  // Protocol-specific (when is_heuristic = false)
  int protocol_id; // protocol ID (only valid for protocols)

  // Heuristic-specific (when is_heuristic = true)
  std::string heuristic_short_name; // unique short name for enabling (only valid for heuristics)
  std::string list_name;            // dissector table this heuristic listens on (e.g., "udp")

  // Child heuristics (only valid for protocols)
  std::vector<EnabledProtocolItem> heuristics; // heuristic dissectors belonging to this protocol
};

// globals

bool wg_init();
bool wg_reload_lua_plugins();
void wg_destroy();
void wg_prefs_apply_all();
std::string wg_ws_version();
SetPrefResponse wg_set_pref(std::string module_name, std::string pref_name, std::string value);
PrefResponse wg_get_pref(std::string module_name, std::string pref_name);
std::string wg_upload_file(std::string name, int buffer_ptr, size_t size);
std::vector<std::string> wg_get_columns();
CheckFilterResponse wg_check_filter(std::string filter);
FilterCompletionResponse wg_complete_filter(std::string field);
std::vector<PrefModule> wg_list_modules();
std::vector<PrefData> wg_list_preferences(std::string module_name);
std::string wg_get_upload_dir();
std::string wg_get_plugins_dir();

// Protocol enable/disable functions
std::vector<ProtocolInfo> wg_list_protocols();
bool wg_set_protocol_enabled(int proto_id, bool enabled);
bool wg_set_protocol_enabled_by_name(std::string proto_name, bool enabled);

// Heuristic dissector enable/disable functions
std::vector<HeuristicInfo> wg_list_heuristic_dissectors();
bool wg_set_heuristic_enabled(std::string short_name, bool enabled);

class DissectSession {
private:
  std::string path;
  capture_file capture_file;
  GHashTable *filter_table;

public:
  DissectSession(std::string _path);
  LoadResponse load();
  FramesResponse getFrames(std::string filter, int skip, int limit);
  Frame getFrame(int number);
  Follow follow(std::string follow, std::string filter);
  TapResponse tap(MapInput taps);
  IoGraphResult iograph(MapInput args);
  DownloadResponse download(std::string token);
  ~DissectSession();
};

#endif