#ifndef WIREGASM_H
#define WIREGASM_H

#include <string>
#include <vector>
#include <glib.h>
#include <wireshark/cfile.h>

using namespace std;

struct ProtoTree
{
  string label;
  string filter;
  int start;
  int length;
  int data_source_idx;
  vector<ProtoTree> tree;
};

struct DataSource
{
  string name;
  string data;
};

struct Frame
{
  int number;
  vector<string> comments;
  vector<DataSource> data_sources;
  vector<ProtoTree> tree;
};

struct FrameMeta
{
  int number;
  bool comments;
  bool ignored;
  bool marked;
  unsigned int bg;
  unsigned int fg;
  vector<string> columns;
};

struct Summary
{
  string filename;
  string file_type; // wtap_file_type_subtype_description
  unsigned int file_length;
  string file_encap_type; // wtap_encap_description
  unsigned int packet_count;
  double start_time;
  double stop_time;
  double elapsed_time;
};

struct LoadResponse
{
  int code;
  string error;
  Summary summary;
};

struct FramesResponse
{
  vector<FrameMeta> frames;
  unsigned int matched;
};

struct CheckFilterResponse
{
  bool ok;
  string error;
};

// globals

bool wg_init();
bool wg_reload_lua_plugins();
void wg_destroy();
string wg_upload_file(string name, int buffer_ptr, size_t size);
vector<string> wg_get_columns();
CheckFilterResponse wg_check_filter(string filter);
string wg_get_upload_dir();
string wg_get_plugins_dir();

class DissectSession
{
private:
  string path;
  capture_file capture_file;
  GHashTable *filter_table;

public:
  DissectSession(string _path);
  LoadResponse load();
  FramesResponse getFrames(string filter, int skip, int limit);
  Frame getFrame(int number);
  ~DissectSession();
};

#endif