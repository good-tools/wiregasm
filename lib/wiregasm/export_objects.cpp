// SPDX-License-Identifier: GPL-2.0-or-later
#include "lib_internal.h"

using namespace std;

static struct wg_export_object_list *wg_eo_list;

static struct wg_export_object_list *
wg_eo_object_list_get_entry_by_type(void *gui_data, const char *tap_type) {
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)gui_data;
  for (; object_list; object_list = object_list->next) {
    if (!strcmp(object_list->type, tap_type))
      return object_list;
  }
  return NULL;
}

static export_object_entry_t *
wg_eo_object_list_get_entry(void *gui_data, int row) {
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)gui_data;

  return (export_object_entry_t *)g_slist_nth_data(object_list->entries, row);
}

static void
wg_eo_object_list_add_entry(void *gui_data, export_object_entry_t *entry) {
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)gui_data;

  object_list->entries = g_slist_append(object_list->entries, entry);
}

GString *wg_session_eo_register_tap_listener(register_eo_t *eo, const char *tap_type, const char *tap_filter, tap_draw_cb tap_draw, void **ptap_data, GFreeFunc *ptap_free) {
  export_object_list_t *eo_object;
  struct wg_export_object_list *object_list;

  object_list = wg_eo_object_list_get_entry_by_type(wg_eo_list, tap_type);
  if (object_list) {
    g_slist_free_full(object_list->entries, (GDestroyNotify)eo_free_entry);
    object_list->entries = NULL;
  } else {
    object_list = g_new(struct wg_export_object_list, 1);
    object_list->type = g_strdup(tap_type);
    object_list->proto = proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo)));
    object_list->entries = NULL;
    object_list->next = wg_eo_list;
    wg_eo_list = object_list;
  }

  eo_object = g_new0(export_object_list_t, 1);
  eo_object->add_entry = wg_eo_object_list_add_entry;
  eo_object->get_entry = wg_eo_object_list_get_entry;
  eo_object->gui_data = (void *)object_list;

  *ptap_data = eo_object;
  *ptap_free = g_free;
  /* need to free only eo_object, object_list need to be kept for potential download */

  return register_tap_listener(
      get_eo_tap_listener_name(eo),
      eo_object, tap_filter,
      0,
      NULL,
      get_eo_packet_func(eo),
      tap_draw,
      NULL);
}

bool wg_session_eo_retap_listener(capture_file *cfile, const char *tap_type, char **err_ret) {
  bool ok = true;
  register_eo_t *eo = NULL;
  GString *tap_error = NULL;
  void *tap_data = NULL;
  GFreeFunc tap_free = NULL;

  // get <name> from eo:<name>, get_eo_by_name only needs the name (http etc.)
  eo = get_eo_by_name(tap_type + 3);
  if (!eo) {
    ok = false;
    *err_ret = g_strdup_printf("eo %s not found", tap_type + 3);
  }

  if (ok) {
    tap_error = wg_session_eo_register_tap_listener(eo, tap_type, NULL, NULL, &tap_data, &tap_free);
    if (tap_error) {
      ok = false;
      *err_ret = g_strdup_printf("error %s", tap_error->str);
      g_string_free(tap_error, TRUE);
    }
  }

  if (ok)
    wg_retap(cfile);

  if (!tap_error)
    remove_tap_listener(tap_data);

  if (tap_free)
    tap_free(tap_data);

  return ok;
}

/**
 * Process download request
 *
 * Input:
 *   (m) token  - token to download
 *
 * Output object with attributes:
 *  (m) error - error message
 *  (o) data - object with attributes:
 *    (o) file - suggested name of file
 *    (o) mime - suggested content type
 *    (o) data - payload base64 encoded
 */
DownloadResponse wg_session_process_download(capture_file *cfile, const char *tok_token) {
  DownloadResponse res;

  if (!tok_token) {
    res.error = "missing token";
    return res;
  }

  if (!strncmp(tok_token, "eo:", 3)) {
    // get eo:<name> from eo:<name>_<row>
    char *tap_type = g_strdup(tok_token);
    char *tmp = strrchr(tap_type, '_');
    char *err_ret = NULL;

    if (tmp)
      *tmp = '\0';

    // if eo:<name> not in wg_eo_list, retap
    if (!wg_eo_object_list_get_entry_by_type(wg_eo_list, tap_type) &&
        !wg_session_eo_retap_listener(cfile, tap_type, &err_ret)) {
      g_free(tap_type);
      if (err_ret)
        res.error = err_ret;
      else
        res.error = "invalid token";
      g_free(err_ret);
      return res;
    }

    g_free(tap_type);

    struct wg_export_object_list *object_list;
    const export_object_entry_t *eo_entry = NULL;

    for (object_list = wg_eo_list; object_list; object_list = object_list->next) {
      size_t eo_type_len = strlen(object_list->type);

      if (!strncmp(tok_token, object_list->type, eo_type_len) && tok_token[eo_type_len] == '_') {
        int row;

        if (sscanf(&tok_token[eo_type_len + 1], "%d", &row) != 1)
          break;

        eo_entry = (export_object_entry_t *)g_slist_nth_data(object_list->entries, row);
        break;
      }
    }

    if (eo_entry) {
      const char *mime = (eo_entry->content_type) ? eo_entry->content_type : "application/octet-stream";
      const char *filename = (eo_entry->filename) ? eo_entry->filename : tok_token;
      res.download.file = filename;
      res.download.mime = mime;
      res.download.data = g_base64_encode(eo_entry->payload_data, eo_entry->payload_len);
    }
    return res;
  } else {
    res.error = "unrecognized token";
    return res;
  }
}

/**
 * Output eo tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) proto      - protocol short name
 *   (m) objects    - array of object with attributes:
 *                  (m) pkt - packet number
 *                  (o) hostname - hostname
 *                  (o) type - content type
 *                  (o) filename - filename
 *                  (m) len - object length
 */
TapExportObject
wg_session_process_tap_eo_cb(void *tapdata) {
  export_object_list_t *tap_object = (export_object_list_t *)tapdata;
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)tap_object->gui_data;
  GSList *slist;
  TapExportObject res;
  res.tap = object_list->type;
  res.type = "eo";
  res.proto = object_list->proto;
  int i = 0;

  for (slist = object_list->entries; slist; slist = slist->next) {
    const export_object_entry_t *eo_entry = (export_object_entry_t *)slist->data;
    ExportObject obj;
    obj.pkt = eo_entry->pkt_num;
    if (eo_entry->hostname)
      obj.hostname = eo_entry->hostname;
    if (eo_entry->content_type)
      obj.type = eo_entry->content_type;
    if (eo_entry->filename)
      obj.filename = eo_entry->filename;
    obj._download = g_strdup_printf("%s_%d", object_list->type, i);
    obj.len = eo_entry->payload_len;
    res.objects.push_back(obj);
    i++;
  }
  return res;
}
