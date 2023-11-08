#include "wiregasm.h"
#include "lib.h"
#include <wsutil/privileges.h>
#include <epan/wslua/init_wslua.h>

using namespace std;

// XXX: g_io_channel_unix_new isn't exported in glib after
// the emscrpten patch, but is referenced in gtester.c
//
// We could use -s ERROR_ON_UNDEFINED_SYMBOLS=0 to avoid defining it here
// GIOChannel* g_io_channel_unix_new (gint fd) {
//   return NULL;
// }

static const char *UPLOAD_DIR = "/uploads";
static gboolean wg_initialized = FALSE;
static e_prefs *prefs_p;

string wg_get_upload_dir()
{
  return string(UPLOAD_DIR);
}

string wg_get_plugins_dir()
{
  return string(get_plugins_dir());
}

vector<string> wg_get_columns()
{
  vector<string> v;

  column_info *cinfo = NULL;
  build_column_format_array(cinfo, prefs_p->num_cols, TRUE);

  for (int i = 0; i < cinfo->num_cols; i++)
  {
    if (!get_column_visible(i))
      continue;

    v.push_back(string(cinfo->columns[i].col_title));
  }

  col_cleanup(cinfo);

  return v;
}

string wg_upload_file(string name, int buffer_ptr, size_t size)
{
  char *path = g_build_filename(UPLOAD_DIR, name.c_str(), nullptr);

  gchar *buffer = (gchar *)buffer_ptr;

  g_file_set_contents(path, buffer, size, NULL);

  string ret(path);
  g_free(path);
  g_free(buffer);
  return ret;
}

bool wg_reload_lua_plugins()
{
  if (!wg_initialized) {
    return false;
  }
  
  wslua_reload_plugins(NULL, NULL);

  on_status(INFO, "Reload complete!");

  return true;
}

bool wg_init()
{
  if (wg_initialized)
  {
    on_status(WARN, "Already initialized!");
    return true;
  }

  on_status(INFO, "Initializing..");

  init_process_policies();
  relinquish_special_privs_perm();

  ws_log_set_level(LOG_LEVEL_INFO);

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
  wtap_init(TRUE);

  on_status(INFO, "Registering all dissectors");

  // register all dissectors
  if (!epan_init(NULL, NULL, TRUE))
  {
    on_status(INFO, "Failure registering dissectors");
    return false;
  }

  on_status(INFO, "Loading preferences");

  prefs_p = epan_load_settings();

  prefs_apply_all();

  on_status(INFO, "Initializing color filters");

  gchar *err_msg;
  if (!color_filters_init(&err_msg, NULL))
  {
    on_status(WARN, err_msg);
    g_free(err_msg);
  }

  wg_initialized = true;

  on_status(INFO, "Initialization complete");

  return wg_initialized;
}

void wg_destroy()
{
  reset_tap_listeners();
  epan_cleanup();
  wtap_cleanup();
  free_progdirs();

  wg_initialized = FALSE;
}

CheckFilterResponse wg_check_filter(string filter)
{
  CheckFilterResponse res;

  char *err_msg = NULL;
  dfilter_t *dfp;

  if (dfilter_compile(filter.c_str(), &dfp, &err_msg))
  {
    dfilter_free(dfp);
    res.ok = true;
  }
  else
  {
    res.ok = false;
  }

  if (err_msg)
  {
    res.error = string(err_msg);
    g_free(err_msg);
  }

  return res;
}

DissectSession::DissectSession(string _path) : path(_path)
{
  cap_file_init(&this->capture_file);
  build_column_format_array(&this->capture_file.cinfo, prefs_p->num_cols, TRUE);
  this->filter_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, wg_session_filter_free);
}

LoadResponse DissectSession::load()
{
  char *err_ret = NULL;

  LoadResponse r;

  summary_tally s;

  int ret = wg_session_process_load(&this->capture_file, this->path.c_str(), &s, &err_ret);

  r.code = ret;

  if (err_ret)
  {
    r.error = string(err_ret);
    g_free(err_ret);
  }

  // populate summary
  r.summary.filename = string(s.filename);
  r.summary.file_type = string(wtap_file_type_subtype_description(s.file_type));
  r.summary.file_encap_type = string(wtap_encap_description(s.file_encap_type));
  r.summary.file_length = s.file_length;
  r.summary.packet_count = s.packet_count;
  r.summary.start_time = s.start_time;
  r.summary.stop_time = s.stop_time;
  r.summary.elapsed_time = s.elapsed_time;

  return r;
}

FramesResponse DissectSession::getFrames(string filter, int skip, int limit)
{
  char *err_ret = NULL;
  FramesResponse ret = wg_process_frames(&this->capture_file, this->filter_table, filter.c_str(), skip, limit, &err_ret);

  // XXX: propagate?
  if (err_ret)
  {
    g_free(err_ret);
  }

  return ret;
}

Frame DissectSession::getFrame(int number)
{
  char *err_ret = NULL;
  Frame f = wg_process_frame(&this->capture_file, number, &err_ret);

  // XXX: propagate?
  if (err_ret)
  {
    g_free(err_ret);
  }

  return f;
}

DissectSession::~DissectSession()
{
  if (this->capture_file.provider.frames != NULL)
  {
    free_frame_data_sequence(this->capture_file.provider.frames);
    this->capture_file.provider.frames = NULL;
  }

  g_hash_table_destroy(this->filter_table);
  epan_free(this->capture_file.epan);
  col_cleanup(&this->capture_file.cinfo);
  cf_close(&this->capture_file);
}
