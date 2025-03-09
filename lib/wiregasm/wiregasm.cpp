#include "wiregasm.h"
#include "lib.h"
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <epan/wslua/init_wslua.h>
#include <epan/prefs-int.h>
#include <epan/prefs.h>
#include <wireshark/ws_version.h>

using namespace std;

// XXX: g_io_channel_unix_new isn't exported in glib after
// the emscrpten patch, but is referenced in gtester.c
//
// We could use -s ERROR_ON_UNDEFINED_SYMBOLS=0 to avoid defining it here
// GIOChannel* g_io_channel_unix_new (gint fd) {
//   return NULL;
// }

static const char *UPLOAD_DIR = "/uploads";
static const char *DEFAULT_PLUGINS_DIR = "/plugins";
static gboolean wg_initialized = FALSE;
static e_prefs *prefs_p;

void
failure_message(const char *msg_format, va_list ap)
{
    va_list ap_copy;
    va_copy(ap_copy, ap);

    int needed_size = vsnprintf(NULL, 0, msg_format, ap) + 1; // Get required size
    char *formatted_msg = (char *)malloc(needed_size);

    if (formatted_msg) {
        vsnprintf(formatted_msg, needed_size, msg_format, ap_copy);
        on_status(ERROR, formatted_msg);
        free(formatted_msg);
    }

    va_end(ap_copy);
}

void
open_failure_message(const char *filename, int err, bool for_writing)
{
}

void
read_failure_message(const char *filename, int err)
{
}

void
write_failure_message(const char *filename, int err)
{
}


void
cfile_open_failure_message(const char *filename, int err, char *err_info)
{
}

void
cfile_dump_open_failure_message(const char *filename, int err, char *err_info,
                                int file_type_subtype)
{
}

void
cfile_read_failure_message(const char *filename, int err, char *err_info)
{
}

void
cfile_write_failure_message(const char *in_filename, const char *out_filename,
                            int err, char *err_info,
                            uint64_t framenum, int file_type_subtype)
{
}

void
cfile_close_failure_message(const char *filename, int err, char *err_info)
{
}

static const struct report_message_routines wg_report_routines = {
    failure_message,
    failure_message,
    open_failure_message,
    read_failure_message,
    write_failure_message,
    cfile_open_failure_message,
    cfile_dump_open_failure_message,
    cfile_read_failure_message,
    cfile_write_failure_message,
    cfile_close_failure_message
};

string wg_ws_version()
{
  char version[32];
  snprintf(version, sizeof(version), "%d.%d.%d", WIRESHARK_VERSION_MAJOR, WIRESHARK_VERSION_MINOR, WIRESHARK_VERSION_MICRO);
  return string(version);
}

string wg_get_upload_dir()
{
  return string(UPLOAD_DIR);
}

string wg_get_plugins_dir()
{
  if (!wg_initialized) {
    return string(DEFAULT_PLUGINS_DIR);
  }

  // get_plugins_dir relies on configuration_init being called
  // which only happens in wg_init
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

  init_report_message("wiregasm", &wg_report_routines);

  // cleanup any previous state
  free_progdirs();

  init_process_policies();
  relinquish_special_privs_perm();

  char * cerr_msg = configuration_init("/wiregasm", NULL);
  if (cerr_msg != NULL) {
    on_status(ERROR, cerr_msg);
    g_free(cerr_msg);
    return false;
  }

  const char * plugin_dir = get_plugins_dir();

  if (plugin_dir == NULL || strlen(plugin_dir) == 0)
  {
    on_status(ERROR, "Failed to get plugins dir");
    return false;
  }

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

void wg_prefs_apply_all()
{
  prefs_apply_all();
}

void wg_set_pref_values(pref_t *pref, PrefData *res)
{
  res->name = prefs_get_name(pref);
  res->title = prefs_get_title(pref);
  res->description = prefs_get_description(pref);

  res->type = prefs_get_type(pref);

  switch (res->type)
  {
    case PREF_UINT:
      res->uint_value = prefs_get_uint_value_real(pref, pref_current);
      if (prefs_get_uint_base(pref) != 10)
        res->uint_base_value = prefs_get_uint_base(pref);
      break;

    case PREF_BOOL:
      res->bool_value = prefs_get_bool_value(pref, pref_current);
      break;

    case PREF_STRING:
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
    case PREF_PASSWORD:
      res->string_value = string(prefs_get_string_value(pref, pref_current));
      break;

    case PREF_RANGE:
    case PREF_DECODE_AS_RANGE:
      {
        char *range_str = range_convert_range(NULL, prefs_get_range_value_real(pref, pref_current));
        res->range_value = string(range_str);
        wmem_free(NULL, range_str);
        break;
      }
    case PREF_ENUM:
      {
        const enum_val_t *enums;

        for (enums = prefs_get_enumvals(pref); enums->name; enums++)
        {
          PrefEnum e;
          e.name = string(enums->name);
          e.description = string(enums->description);
          e.value = enums->value;
          e.selected = false;
          
          if (enums->value == prefs_get_enum_value(pref, pref_current))
          {
            e.selected = true;
          }

          res->enum_value.push_back(e);
        }
        break;
      }

    case PREF_UAT:
    case PREF_COLOR:
    case PREF_CUSTOM:
    case PREF_STATIC_TEXT:
    case PREF_OBSOLETE:
        /* TODO */
        break;
  }
}

PrefResponse wg_get_pref(string module_name, string pref_name)
{
  PrefResponse res;
  res.code = -1;

  pref_t *pref = prefs_find_preference(prefs_find_module(module_name.c_str()), pref_name.c_str());
  if (pref == NULL) {
      return res;
  }

  res.code = 0;

  wg_set_pref_values(pref, &res.data);

  return res;
}

struct PrefModuleHolder
{
  vector<PrefModule> modules;
  bool root;
};

guint wg_list_modules_cb(module_t *module, gpointer user_data)
{
  PrefModuleHolder *holder = (PrefModuleHolder *)user_data;

  if (holder->root && module->parent != NULL)
  {
    return 0;
  }

  PrefModuleHolder subholder;
  subholder.root = false;

  PrefModule m;

  m.use_gui = module->use_gui;

  if (module->name) {
    m.name = string(module->name);
  }

  if (module->title) {
    m.title = string(module->title);
  }

  if (module->description) {
    m.description = string(module->description);
  }

  if (prefs_module_has_submodules(module))
  {
    prefs_modules_foreach_submodules(module, wg_list_modules_cb, &subholder);
    m.submodules = subholder.modules;
  }

  holder->modules.push_back(m);

  return 0;
}


vector<PrefModule> wg_list_modules()
{
  PrefModuleHolder holder;
  holder.root = true;
  prefs_modules_foreach(wg_list_modules_cb, &holder);
  return holder.modules;
}

guint wg_list_preferences_cb(pref_t *pref, gpointer user_data)
{
  vector<PrefData> *prefs = (vector<PrefData> *)user_data;

  PrefData p;
  wg_set_pref_values(pref, &p);
  prefs->push_back(p);

  return 0;
}

vector<PrefData> wg_list_preferences(string module_name)
{
  vector<PrefData> prefs;
  module_t * mod = prefs_find_module(module_name.c_str());

  if (mod != NULL)
  {
    prefs_pref_foreach(mod, wg_list_preferences_cb, &prefs);
  }

  return prefs;
}

SetPrefResponse wg_set_pref(string module_name, string pref_name, string value)
{
  SetPrefResponse res;

  char pref[4096];
  prefs_set_pref_e ret;
  char *errmsg = NULL;

  snprintf(pref, sizeof(pref), "%s.%s:%s", module_name.c_str(), pref_name.c_str(), value.c_str());

  ret = prefs_set_pref(pref, &errmsg);

  res.code = ret;

  if (errmsg)
  {
    res.error = string(errmsg);
    g_free(errmsg);
  }

  return res;
}

CheckFilterResponse wg_check_filter(string filter)
{
  CheckFilterResponse res;

  df_error_t *err_info = NULL;
  dfilter_t *dfp;

  if (dfilter_compile(filter.c_str(), &dfp, &err_info))
  {
    dfilter_free(dfp);
    res.ok = true;
  }
  else
  {
    res.ok = false;
  }

  if (err_info)
  {
    res.error = string(err_info->msg);
    g_free(err_info);
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

Follow DissectSession::follow(string follow, string filter)
{
  char *err_ret = NULL;
  Follow ret = wg_process_follow(&this->capture_file, follow.c_str(), filter.c_str(), &err_ret);

  // XXX: propagate?
  if (err_ret)
  {
    g_free(err_ret);
  }

  return ret;
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

FilterCompletionResponse wg_complete_filter(string field)
{
  FilterCompletionResponse res;
  res.fields = wg_session_process_complete(field.c_str());
  return res;
}
