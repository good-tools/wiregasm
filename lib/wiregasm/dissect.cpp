// SPDX-License-Identifier: GPL-2.0-or-later
#include "lib_internal.h"

using namespace std;

void wg_session_filter_free(gpointer data) {
  struct wg_filter_item *l = (struct wg_filter_item *)data;

  g_free(l->filtered);
  g_free(l);
}

vector<ProtoTree>
wg_session_process_frame_cb_tree(epan_dissect_t *edt, proto_tree *tree, tvbuff_t **tvbs, gboolean display_hidden) {
  proto_node *node;

  vector<ProtoTree> res;

  for (node = tree->first_child; node; node = node->next) {
    field_info *finfo = PNODE_FINFO(node);

    if (!finfo)
      continue;

    if (!display_hidden && FI_GET_FLAG(finfo, FI_HIDDEN))
      continue;

    ProtoTree t;

    if (!finfo->rep) {
      char label_str[ITEM_LABEL_LENGTH];

      label_str[0] = '\0';
      proto_item_fill_label(finfo, label_str, NULL);
      t.label = string(label_str);
    } else {
      t.label = string(finfo->rep->representation);
    }

    t.data_source_idx = 0;
    if (finfo->ds_tvb && tvbs && tvbs[0] != finfo->ds_tvb) {
      int idx;

      for (idx = 1; tvbs[idx]; idx++) {
        if (tvbs[idx] == finfo->ds_tvb) {
          t.data_source_idx = idx;
          break;
        }
      }
    }

    t.start = 0, t.length = 0;

    if (finfo->start >= 0 && finfo->length > 0) {
      t.start = finfo->start, t.length = finfo->length;
    }

    if (FI_GET_FLAG(finfo, PI_SEVERITY_MASK)) {
      t.severity = try_val_to_str(FI_GET_FLAG(finfo, PI_SEVERITY_MASK), expert_severity_vals);
    }

    if (finfo->hfinfo) {
      char *filter;

      if (finfo->hfinfo->type == FT_PROTOCOL) {
        t.type = "proto";
      } else if (finfo->hfinfo->type == FT_FRAMENUM) {
        t.type = "framenum";
        t.fnum = fvalue_get_uinteger(finfo->value);
      } else if (FI_GET_FLAG(finfo, FI_URL) && finfo->hfinfo->type == FT_STRING) {
        char *url = fvalue_to_string_repr(NULL, finfo->value, FTREPR_DISPLAY, finfo->hfinfo->display);
        t.type = "url";
        t.url = url;
        wmem_free(NULL, url);
      }

      filter = proto_construct_match_selected_string(finfo, edt);
      if (filter) {
        t.filter = string(filter);

        wmem_free(NULL, filter);
      }
    }

    if (((proto_tree *)node)->first_child) {
      vector<ProtoTree> children = wg_session_process_frame_cb_tree(edt, (proto_tree *)node, tvbs, display_hidden);
      t.tree = children;
    }

    res.push_back(t);
  }

  return res;
}

struct VisitData {
  packet_info *pi;
  vector<vector<string>> *followArray;
};

static bool
wg_session_follower_visit_cb(const void *key _U_, void *value, void *user_data) {
  register_follow_t *follower = (register_follow_t *)value;
  VisitData *visitData = (VisitData *)user_data;
  packet_info *pi = visitData->pi;
  vector<vector<string>> *followArray = visitData->followArray;

  const int proto_id = get_follow_proto_id(follower);
  guint32 ignore_stream;
  guint32 ignore_sub_stream;

  if (proto_is_frame_protocol(pi->layers, proto_get_protocol_filter_name(proto_id))) {
    const char *layer_proto = proto_get_protocol_short_name(find_protocol_by_id(proto_id));
    char *follow_filter;

    follow_filter = get_follow_conv_func(follower)(NULL, pi, &ignore_stream, &ignore_sub_stream);
    // [['HTTP', 'tcp.stream eq 0'],['TCP', 'tcp.stream eq 0']]
    vector<string> follow;
    follow.push_back(static_cast<string>(layer_proto));
    follow.push_back(static_cast<string>(follow_filter));
    followArray->push_back(follow);
    g_free(follow_filter);
  }
  return false;
}

void wg_session_process_frame_cb(capture_file *cfile, epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo _U_, const GSList *data_src, void *data) {
  packet_info *pi = &edt->pi;
  frame_data *fdata = pi->fd;
  wtap_block_t pkt_block = fdata->has_modified_block ? cap_file_provider_get_modified_block(&cfile->provider, fdata) : pi->rec->block;

  Frame *f = (Frame *)data;

  if (pkt_block) {
    guint n = wtap_block_count_option(pkt_block, OPT_COMMENT);

    for (guint i = 0; i < n; i++) {
      gchar *comment;
      if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, i, &comment)) {
        f->comments.push_back(std::string(comment));
      }
      g_free(comment);
    }
  }

  if (tree) {
    tvbuff_t **tvbs = NULL;

    /* arrayize data src, to speedup searching for ds_tvb index */
    if (data_src && data_src->next /* only needed if there are more than one data source */) {
      guint count = g_slist_length((GSList *)data_src);
      tvbs = (tvbuff_t **)g_malloc0((count + 1) * sizeof(*tvbs));

      for (guint i = 0; i < count; i++) {
        const struct data_source *src = (const struct data_source *)g_slist_nth_data((GSList *)data_src, i);

        tvbs[i] = get_data_source_tvb(src);
      }

      tvbs[count] = NULL;
    }

    vector<ProtoTree> children = wg_session_process_frame_cb_tree(edt, tree, tvbs, FALSE);
    f->tree = children;

    g_free(tvbs);
  }

  while (data_src) {
    struct data_source *src = (struct data_source *)data_src->data;
    tvbuff_t *tvb;
    guint length;

    tvb = get_data_source_tvb(src);
    length = tvb_captured_length(tvb);
    char *src_name = get_data_source_description(src);
    const guchar *cp = tvb_get_ptr(tvb, 0, length);
    char *encoded = g_base64_encode(cp, length);
    f->data_sources.push_back(DataSource{string(src_name), string(encoded)});
    g_free(encoded);
    wmem_free(NULL, src_name);

    data_src = data_src->next;
  }

  VisitData visitData;
  visitData.pi = pi;
  vector<vector<string>> followArray;   // Initialize the followArray vector
  visitData.followArray = &followArray; // Assign the address of followArray to visitData.followArray
  follow_iterate_followers(wg_session_follower_visit_cb, &visitData);
  // Assign followArray to f->follow
  for (const auto &follow : *visitData.followArray) {
    f->follow.push_back(follow);
  }
}

Follow wg_session_process_follow(capture_file *cfile, const char *tok_follow, const char *tok_filter, char **err_ret) {
  register_follow_t *follower;
  GString *tap_error;

  follow_info_t *follow_info;

  const char *host;
  char *port;
  Follow f;

  follower = get_follow_by_name(tok_follow);
  if (!follower) {
    *err_ret = g_strdup_printf("follower=%s not found", tok_follow);
    return f;
  }
  /* follow_reset_stream ? */
  follow_info = g_new0(follow_info_t, 1);
  /* gui_data, filter_out_filter not set, but not used by dissector */

  tap_error = register_tap_listener(get_follow_tap_string(follower), follow_info, tok_filter, 0, NULL, get_follow_tap_handler(follower), NULL, NULL);
  if (tap_error) {
    *err_ret = g_strdup_printf("name=%s error=%s", tok_follow, tap_error->str);
    g_string_free(tap_error, TRUE);
    g_free(follow_info);
    return f;
  }

  wg_retap(cfile);
  /* Server information: hostname, port, bytes sent */
  host = address_to_name(&follow_info->server_ip);
  f.shost = host;

  port = get_follow_port_to_display(follower)(NULL, follow_info->server_port);
  f.sport = port;
  wmem_free(NULL, port);
  f.sbytes = follow_info->bytes_written[0];

  /* Client information: hostname, port, bytes sent */
  host = address_to_name(&follow_info->client_ip);
  f.chost = host;

  port = get_follow_port_to_display(follower)(NULL, follow_info->client_port);
  f.cport = port;
  wmem_free(NULL, port);
  f.cbytes = follow_info->bytes_written[1];

  if (follow_info->payload) {
    follow_record_t *follow_record;
    GList *cur;
    for (cur = g_list_last(follow_info->payload); cur; cur = g_list_previous(cur)) {
      follow_record = (follow_record_t *)cur->data;
      char *encoded = g_base64_encode(follow_record->data->data, follow_record->data->len);
      f.payloads.push_back(FollowPayload{int(follow_record->packet_num), string(encoded), static_cast<unsigned int>(follow_record->is_server ? 1 : 0)});
      g_free(encoded);
    }
  }

  remove_tap_listener(follow_info);
  follow_info_free(follow_info);
  return f;
}

void wg_session_process_frames_cb(capture_file *cfile, epan_dissect_t *edt, proto_tree *tree _U_,
                                  struct epan_column_info *cinfo, const GSList *data_src _U_, void *data) {
  packet_info *pi = &edt->pi;
  frame_data *fdata = pi->fd;
  wtap_block_t pkt_block = NULL;
  char *comment;

  vector<FrameMeta> *store = (vector<FrameMeta> *)data;

  FrameMeta f;
  f.number = pi->num;

  for (int col = 0; col < cinfo->num_cols; ++col) {
    f.columns.push_back(string(get_column_text(cinfo, col)));
  }

  /*
   * Get the block for this record, if it has one.
   */
  if (fdata->has_modified_block)
    pkt_block = cap_file_provider_get_modified_block(&cfile->provider, fdata);
  else
    pkt_block = pi->rec->block;

  f.comments = false;
  f.ignored = false;
  f.marked = false;
  f.bg = 1;
  f.fg = 0;

  /*
   * Does this record have any comments?
   */
  if (pkt_block != NULL &&
      WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, 0, &comment))
    f.comments = true;

  if (fdata->ignored)
    f.ignored = true;

  if (fdata->marked)
    f.marked = true;

  if (fdata->color_filter) {
    f.bg = color_t_to_rgb(&fdata->color_filter->bg_color);
    f.fg = color_t_to_rgb(&fdata->color_filter->fg_color);
  }

  store->push_back(f);
}

enum dissect_request_status
wg_dissect_request(capture_file *cfile, guint32 framenum, guint32 frame_ref_num,
                   guint32 prev_dis_num, wtap_rec *rec,
                   column_info *cinfo, guint32 dissect_flags,
                   wg_dissect_func_t cb, void *data,
                   int *err, gchar **err_info) {
  frame_data *fdata;
  epan_dissect_t edt;
  gboolean create_proto_tree;

  fdata = wg_get_frame(cfile, framenum);
  if (fdata == NULL)
    return DISSECT_REQUEST_NO_SUCH_FRAME;

  if (!wtap_seek_read(cfile->provider.wth, fdata->file_off, rec, err, err_info)) {
    if (cinfo != NULL)
      col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);
    return DISSECT_REQUEST_READ_ERROR; /* error reading the record */
  }

  create_proto_tree = ((dissect_flags & WG_DISSECT_FLAG_PROTO_TREE) ||
                       ((dissect_flags & WG_DISSECT_FLAG_COLOR) && color_filters_used()) ||
                       (cinfo && have_custom_cols(cinfo)));
  epan_dissect_init(&edt, cfile->epan, create_proto_tree, (dissect_flags & WG_DISSECT_FLAG_PROTO_TREE));

  if (dissect_flags & WG_DISSECT_FLAG_COLOR) {
    color_filters_prime_edt(&edt);
    fdata->need_colorize = 1;
  }

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  fdata->ref_time = (framenum == frame_ref_num);
  fdata->frame_ref_num = frame_ref_num;
  fdata->prev_dis_num = prev_dis_num;
  epan_dissect_run(&edt, cfile->cd_t, rec,
                   fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE /* fill_fd_columns */);
  }

  cb(cfile, &edt, (dissect_flags & WG_DISSECT_FLAG_PROTO_TREE) ? edt.tree : NULL,
     cinfo, (dissect_flags & WG_DISSECT_FLAG_BYTES) ? edt.pi.data_src : NULL,
     data);

  wtap_rec_reset(rec);
  epan_dissect_cleanup(&edt);
  return DISSECT_REQUEST_SUCCESS;
}

int wg_filter(capture_file *cfile, const char *dftext, guint8 **result, guint *passed) {
  dfilter_t *dfcode = NULL;

  guint32 framenum, prev_dis_num = 0;
  guint32 frames_count;
  wtap_rec rec;
  int err;
  char *err_info = NULL;

  guint passed_frames = 0;
  guint8 *result_bits;
  guint8 passed_bits;

  epan_dissect_t edt;

  df_error_t *dferr = NULL;
  if (!dfilter_compile(dftext, &dfcode, &dferr)) {
    g_free(dferr);
    return -1;
  }

  /* if dfilter_compile() success, but (dfcode == NULL) all frames are matching */
  if (dfcode == NULL) {
    *result = NULL;
    *passed = cfile->count;
    return 0;
  }

  frames_count = cfile->count;

  wtap_rec_init(&rec, 1514);
  epan_dissect_init(&edt, cfile->epan, TRUE, FALSE);

  passed_bits = 0;
  result_bits = (guint8 *)g_malloc(2 + (frames_count / 8));

  for (framenum = 1; framenum <= frames_count; framenum++) {
    frame_data *fdata = wg_get_frame(cfile, framenum);

    if ((framenum & 7) == 0) {
      result_bits[(framenum / 8) - 1] = passed_bits;
      passed_bits = 0;
    }

    if (!wtap_seek_read(cfile->provider.wth, fdata->file_off, &rec, &err, &err_info))
      break;

    /* frame_data_set_before_dissect */
    epan_dissect_prime_with_dfilter(&edt, dfcode);

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = prev_dis_num;
    epan_dissect_run(&edt, cfile->cd_t, &rec,
                     fdata, NULL);

    if (dfilter_apply_edt(dfcode, &edt)) {
      passed_bits |= (1 << (framenum % 8));
      prev_dis_num = framenum;
      passed_frames++;
    }

    /* if passed or ref -> frame_data_set_after_dissect */

    wtap_rec_reset(&rec);
    epan_dissect_reset(&edt);
  }

  if ((framenum & 7) == 0)
    framenum--;
  result_bits[framenum / 8] = passed_bits;

  wtap_rec_cleanup(&rec);
  epan_dissect_cleanup(&edt);

  dfilter_free(dfcode);

  *result = result_bits;
  *passed = passed_frames;

  return framenum;
}

const struct wg_filter_item *
session_filter_data(GHashTable *filter_table, capture_file *cfile, const char *filter) {
  struct wg_filter_item *l;

  l = (struct wg_filter_item *)g_hash_table_lookup(filter_table, filter);
  if (!l) {
    guint8 *filtered = NULL;
    guint passed = 0;

    int ret = wg_filter(cfile, filter, &filtered, &passed);

    if (ret == -1)
      return NULL;

    l = g_new(struct wg_filter_item, 1);
    l->filtered = filtered;
    l->passed = passed;

    g_hash_table_insert(filter_table, g_strdup(filter), l);
  }

  return l;
}

Frame wg_process_frame(capture_file *cfile, guint32 framenum, char **err_ret) {
  column_info *cinfo = NULL;

  guint32 ref_frame_num, prev_dis_num;
  guint32 dissect_flags = WG_DISSECT_FLAG_NULL;
  wtap_rec rec; /* Record metadata */
  enum dissect_request_status status;
  int err;
  gchar *err_info;

  ref_frame_num = (framenum != 1) ? 1 : 0;
  prev_dis_num = framenum - 1;

  dissect_flags |= WG_DISSECT_FLAG_PROTO_TREE;
  dissect_flags |= WG_DISSECT_FLAG_BYTES;
  dissect_flags |= WG_DISSECT_FLAG_COLUMNS;
  dissect_flags |= WG_DISSECT_FLAG_COLOR;
  cinfo = &cfile->cinfo;

  wtap_rec_init(&rec, 1514);

  Frame f;
  f.number = framenum;

  status = wg_dissect_request(cfile, framenum, ref_frame_num, prev_dis_num,
                              &rec, cinfo, dissect_flags,
                              &wg_session_process_frame_cb, &f, &err, &err_info);
  switch (status) {
  case DISSECT_REQUEST_SUCCESS:
    /* success */
    break;

  case DISSECT_REQUEST_NO_SUCH_FRAME:
    *err_ret = g_strdup_printf("Invalid frame - The frame number requested is out of range");
    break;

  case DISSECT_REQUEST_READ_ERROR:
    *err_ret = g_strdup_printf("Read error - The frame could not be read from the file");
    g_free(err_info);
    break;
  }

  wtap_rec_cleanup(&rec);

  return f;
}

FramesResponse wg_process_frames(capture_file *cfile, GHashTable *filter_table, const char *filter, guint32 skip, guint32 limit, char **err_ret) {
  const guint8 *filter_data = NULL;

  wtap_rec rec; /* Record metadata */
  column_info *cinfo = &cfile->cinfo;

  FramesResponse result;
  result.matched = 0;

  vector<FrameMeta> res;

  const struct wg_filter_item *filter_item;

  filter_item = session_filter_data(filter_table, cfile, filter);
  if (!filter_item) {
    *err_ret = g_strdup_printf("Filter expression invalid");
    return result;
  }

  filter_data = filter_item->filtered;

  wtap_rec_init(&rec, 1514);

  for (guint32 framenum = 1; framenum <= cfile->count; framenum++) {
    frame_data *fdata;
    enum dissect_request_status status;
    int err;
    gchar *err_info;

    if (filter_data && !(filter_data[framenum / 8] & (1 << (framenum % 8))))
      continue;

    if (skip) {
      skip--;
      continue;
    }

    fdata = wg_get_frame(cfile, framenum);
    status = wg_dissect_request(cfile, framenum,
                                (framenum != 1) ? 1 : 0, framenum - 1,
                                &rec, cinfo,
                                (fdata->color_filter == NULL) ? WG_DISSECT_FLAG_COLOR : WG_DISSECT_FLAG_NULL,
                                &wg_session_process_frames_cb, &res,
                                &err, &err_info);
    switch (status) {
    case DISSECT_REQUEST_SUCCESS:
      break;

    case DISSECT_REQUEST_NO_SUCH_FRAME:
      /* XXX - report the error. */
      break;

    case DISSECT_REQUEST_READ_ERROR:
      /*
       * Free up the error string.
       * XXX - report the error.
       */
      g_free(err_info);
      break;
    }

    if (limit && --limit == 0)
      break;
  }

  if (cinfo != &cfile->cinfo)
    col_cleanup(cinfo);

  wtap_rec_cleanup(&rec);

  result.matched = filter_item->passed;
  result.frames = res;

  return result;
}

Follow wg_process_follow(capture_file *cfile, const char *follow, const char *filter, char **err_ret) {
  Follow fdata = wg_session_process_follow(cfile, follow, filter, err_ret);
  return fdata;
}

/**
 * Process complete request
 *
 * Input:
 *   field - field to be completed
 *
 * Output object with :
 *   err - always 0attributes
 *   field - array of object with attributes:
 *         field - field text
 *         type - field type (FT_ number)
 *         name - field name
 */
vector<CompleteField>
wg_session_process_complete(const char *tok_field) {
  vector<CompleteField> res;
  if (tok_field != NULL && tok_field[0]) {
    const size_t filter_length = strlen(tok_field);
    const int filter_with_dot = !!strchr(tok_field, '.');

    void *proto_cookie;
    void *field_cookie;
    int proto_id;

    for (proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie)) {
      protocol_t *protocol = find_protocol_by_id(proto_id);
      const char *protocol_filter;
      const char *protocol_name;
      header_field_info *hfinfo;

      if (!proto_is_protocol_enabled(protocol))
        continue;

      protocol_name = proto_get_protocol_long_name(protocol);
      protocol_filter = proto_get_protocol_filter_name(proto_id);

      if (strlen(protocol_filter) >= filter_length && !g_ascii_strncasecmp(tok_field, protocol_filter, filter_length)) {
        res.push_back(CompleteField{string(protocol_filter), static_cast<int>(FT_PROTOCOL), string(protocol_name)});
      }

      if (!filter_with_dot)
        continue;

      for (hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
        if (hfinfo->same_name_prev_id != -1) /* ignore duplicate names */
          continue;

        if (strlen(hfinfo->abbrev) >= filter_length && !g_ascii_strncasecmp(tok_field, hfinfo->abbrev, filter_length)) {
          CompleteField f;
          {
            f.field = string(hfinfo->abbrev);
            /* XXX, skip displaying name, if there are multiple (to not confuse user) */
            if (hfinfo->same_name_next == NULL) {
              f.type = static_cast<int>(hfinfo->type);
              f.name = string(hfinfo->name);
            }
          }
          res.push_back(f);
        }
      }
    }
  }
  return res;
}
