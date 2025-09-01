#ifndef WIREGASM_H
#define WIREGASM_H

#include <glib.h>
#include <map>
#include <string>
#include <vector>
#include <wireshark/cfile.h>

using namespace std;

struct ProtoTree {
  string label;
  string filter;
  string severity;
  string type;
  string url;
  unsigned int fnum;
  int start;
  int length;
  int data_source_idx;
  vector<ProtoTree> tree;
};

struct FollowPayload {
  int number;
  string data;
  unsigned int server;
};

struct Follow {
  string shost;
  string sport;
  unsigned int sbytes;
  string chost;
  string cport;
  unsigned int cbytes;
  vector<FollowPayload> payloads;
};

struct DataSource {
  string name;
  string data;
};

struct CompleteField {
  string field;
  int type;
  string name;
};

struct Frame {
  int number;
  vector<string> comments;
  vector<DataSource> data_sources;
  vector<ProtoTree> tree;
  vector<vector<string>> follow;
};

struct FrameMeta {
  int number;
  bool comments;
  bool ignored;
  bool marked;
  unsigned int bg;
  unsigned int fg;
  vector<string> columns;
};

struct Summary {
  string filename;
  string file_type; // wtap_file_type_subtype_description
  unsigned int file_length;
  string file_encap_type; // wtap_encap_description
  unsigned int packet_count;
  double start_time;
  double stop_time;
  double elapsed_time;
};

struct LoadResponse {
  int code;
  string error;
  Summary summary;
};

struct FramesResponse {
  vector<FrameMeta> frames;
  unsigned int matched;
};

struct CheckFilterResponse {
  bool ok;
  string error;
};

struct IoGraph {
  vector<float> items;
};

struct IoGraphResult {
  string error;
  vector<IoGraph> iograph;
};

// base struct
struct TapValue {
  string tap;
  string type;
  string proto;
  virtual ~TapValue() = default;
};

struct GeoIp {
  string country;
  string country_iso;
  string city;
  string as_org;
  uint32_t as;
  double lat;
  double lon;
};

struct Conversation {
  string saddr;             // source address
  string daddr;             // destination address
  string sport;             // source port
  string dport;             // destination port
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
  string filter;            // filter string
};

struct Host {
  string host;              // host address
  string port;              // host port
  unsigned txf;             // number of transmitted frames
  unsigned txb;             // number of transmitted bytes
  unsigned rxf;             // number of received frames
  unsigned rxb;             // number of received bytes
  unsigned tx_frames_total; // number of transmitted frames total
  unsigned rx_frames_total; // number of received frames total
  unsigned tx_bytes_total;  // number of transmitted bytes total
  unsigned rx_bytes_total;  // number of received bytes total
  bool filtered;            // whether the entry contains only filtered data
  string filter;            // filter string
};

struct ExportObject {
  unsigned pkt;
  string hostname;
  string type;
  string filename;
  string _download;
  size_t len;
};

// derived structs
struct TapConvResponse : TapValue {
  bool geoip;
  vector<Conversation> convs;
  vector<Host> hosts;
};

struct TapExportObject : TapValue {
  vector<ExportObject> objects;
};

// response struct
struct TapResponse {
  vector<shared_ptr<TapValue>> taps;
  string error;
};

using MapInput = std::map<string, string>;

struct PrefEnum {
  string name;
  string description;
  int value;
  bool selected;
};

struct PrefData {
  string name;
  string title;
  string description;

  int type;

  // TODO: make these optional, emscripten now supports optional fields
  uint uint_value;
  uint uint_base_value;
  bool bool_value;
  string string_value;
  vector<PrefEnum> enum_value;
  string range_value;
};

struct SetPrefResponse {
  int code;
  string error;
};

struct PrefResponse {
  int code;
  PrefData data;
};

struct PrefModule {
  string name;
  string title;
  string description;
  vector<PrefModule> submodules;
  bool use_gui;
};

struct FilterCompletionResponse {
  vector<CompleteField> fields;
};

struct Download {
  string file;
  string mime;
  string data;
};

struct DownloadResponse {
  string error;
  Download download;
};

// globals

bool wg_init();
bool wg_reload_lua_plugins();
void wg_destroy();
void wg_prefs_apply_all();
string wg_ws_version();
SetPrefResponse wg_set_pref(string module_name, string pref_name, string value);
PrefResponse wg_get_pref(string module_name, string pref_name);
string wg_upload_file(string name, int buffer_ptr, size_t size);
vector<string> wg_get_columns();
CheckFilterResponse wg_check_filter(string filter);
FilterCompletionResponse wg_complete_filter(string field);
vector<PrefModule> wg_list_modules();
vector<PrefData> wg_list_preferences(string module_name);
string wg_get_upload_dir();
string wg_get_plugins_dir();

class DissectSession {
private:
  string path;
  capture_file capture_file;
  GHashTable *filter_table;

public:
  DissectSession(string _path);
  LoadResponse load();
  FramesResponse getFrames(string filter, int skip, int limit);
  Frame getFrame(int number);
  Follow follow(string follow, string filter);
  TapResponse tap(MapInput taps);
  IoGraphResult iograph(MapInput args);
  DownloadResponse download(string token);
  ~DissectSession();
};

#endif
