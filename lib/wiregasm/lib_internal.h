// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WG_LIB_INTERNAL_H
#define WG_LIB_INTERNAL_H

// Shared between the lib/wiregasm/*.cpp files; not part of the public API.

#include "lib.h"

struct wg_conv_tap_data {
  const char *type;
  conv_hash_t hash;
  bool resolve_name;
  bool resolve_port;
};

struct wg_export_object_list {
  struct wg_export_object_list *next;

  char *type;
  const char *proto;
  GSList *entries;
};

// capture.cpp
frame_data *wg_get_frame(capture_file *cfile, guint32 framenum);
int wg_retap(capture_file *cfile);

// export_objects.cpp
GString *wg_session_eo_register_tap_listener(register_eo_t *eo, const char *tap_type, const char *tap_filter,
                                             tap_draw_cb tap_draw, void **ptap_data, GFreeFunc *ptap_free);
TapExportObject wg_session_process_tap_eo_cb(void *tapdata);

#endif
