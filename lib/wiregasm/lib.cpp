#include "lib.h"
#include "wiregasm.h"

static guint32 cum_bytes;
static frame_data ref_frame;

struct wg_export_object_list
{
  struct wg_export_object_list *next;

  char *type;
  const char *proto;
  GSList *entries;
};

static struct wg_export_object_list *wg_eo_list;

// struct wg_download_rtp
// {
//     rtpstream_id_t id;
//     GSList *packets;
//     double start_time;
// };

void cf_close(capture_file *cf)
{
  if (cf->state == FILE_CLOSED)
    return; /* Nothing to do */

  if (cf->provider.wth != NULL)
  {
    wtap_close(cf->provider.wth);
    cf->provider.wth = NULL;
  }
  /* We have no file open... */
  if (cf->filename != NULL)
  {
    /* If it's a temporary file, remove it. */
    if (cf->is_tempfile)
    {
      remove(cf->filename);
    }
    g_free(cf->filename);
    cf->filename = NULL;
  }

  /* We have no file open. */
  cf->state = FILE_CLOSED;
}

frame_data *
wg_get_frame(capture_file *cfile, guint32 framenum)
{
  return frame_data_sequence_find(cfile->provider.frames, framenum);
}

static const nstime_t *
wg_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  if (prov->frames)
  {
    frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

    return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
wg_epan_new(capture_file *cf)
{
  static const struct packet_provider_funcs funcs = {
      wg_get_frame_ts,
      cap_file_provider_get_interface_name,
      cap_file_provider_get_interface_description,
      cap_file_provider_get_modified_block};

  return epan_new(&cf->provider, &funcs);
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap *wth;
  gchar *err_info;

  wth = wtap_open_offline(fname, type, err, &err_info, TRUE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

  cf->provider.wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t = wtap_file_type_subtype(cf->provider.wth);
  cf->open_type = type;
  cf->count = 0;
  cf->drops_known = FALSE;
  cf->drops = 0;
  cf->snap = wtap_snapshot_length(cf->provider.wth);
  nstime_set_zero(&cf->elapsed_time);
  cf->provider.ref = NULL;
  cf->provider.prev_dis = NULL;
  cf->provider.prev_cap = NULL;

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = wg_epan_new(cf);

  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->provider.wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->provider.wth, (wtap_new_ipv6_callback_t)add_ipv6_name);
  wtap_set_cb_new_secrets(cf->provider.wth, secrets_wtap_callback);

  return CF_OK;

fail:
  return CF_ERROR;
}

cf_status_t
wg_cf_open(capture_file *cfile, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  return cf_open(cfile, fname, type, is_tempfile, err);
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, wtap_rec *rec, Buffer *buf)
{
  frame_data fdlocal;
  gboolean passed;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  /* The frame number of this packet, if we add it to the set of frames,
     would be one more than the count of frames in the file so far. */
  frame_data_init(&fdlocal, cf->count + 1, rec, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or display filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt)
  {
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_with_dfilter(edt, cf->rfcode);

    if (cf->dfcode)
      epan_dissect_prime_with_dfilter(edt, cf->dfcode);

    /* This is the first and only pass, so prime the epan_dissect_t
       with the hfids postdissectors want on the first pass. */
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &cf->provider.ref, cf->provider.prev_dis);
    if (cf->provider.ref == &fdlocal)
    {
      ref_frame = fdlocal;
      cf->provider.ref = &ref_frame;
    }

    epan_dissect_run(edt, cf->cd_t, rec,
                     frame_tvbuff_new_buffer(&cf->provider, &fdlocal, buf),
                     &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed)
  {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cf->provider.prev_cap = cf->provider.prev_dis = frame_data_sequence_add(cf->provider.frames, &fdlocal);

    cf->f_datalen = offset + fdlocal.cap_len;
    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode)
    {
      if (dfilter_apply_edt(cf->dfcode, edt))
      {
        g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->provider.frames);
      }
    }

    cf->count++;
  }
  else
  {
    /* if we don't add it to the frame_data_sequence, clean it up right now
     * to avoid leaks */
    frame_data_destroy(&fdlocal);
  }

  if (edt)
    epan_dissect_reset(edt);

  return passed;
}

static int
load_cap_file(capture_file *cf, int max_packet_count, gint64 max_byte_count, summary_tally *summary)
{
  int err;
  gchar *err_info = NULL;
  gint64 data_offset;
  wtap_rec rec;
  Buffer buf;
  epan_dissect_t *edt = NULL;

  {
    /* Allocate a frame_data_sequence for all the frames. */
    cf->provider.frames = new_frame_data_sequence();

    {
      gboolean create_proto_tree;

      /*
       * Determine whether we need to create a protocol tree.
       * We do if:
       *
       *    we're going to apply a read filter;
       *
       *    we're going to apply a display filter;
       *
       *    a postdissector wants field values or protocols
       *    on the first pass.
       */
      create_proto_tree =
          (cf->rfcode != NULL || cf->dfcode != NULL || postdissectors_want_hfids());

      /* We're not going to display the protocol tree on this pass,
         so it's not going to be "visible". */
      edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
    }

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    while (wtap_read(cf->provider.wth, &rec, &buf, &err, &err_info, &data_offset))
    {
      if (process_packet(cf, edt, data_offset, &rec, &buf))
      {
        wtap_rec_reset(&rec);
        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ((--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count))
        {
          err = 0; /* This is not an error */
          break;
        }
      }
    }

    if (edt)
    {
      epan_dissect_free(edt);
      edt = NULL;
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->provider.wth);

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;
  }

  cf->lnk_t = wtap_file_encap(cf->provider.wth);
  summary_fill_in(cf, summary);

  if (err_info)
  {
    // XXX: propagate?
    g_free(err_info);
  }

  return err;
}

int wg_load_cap_file(capture_file *cfile, summary_tally *summary)
{
  return load_cap_file(cfile, 0, 0, summary);
}

int wg_retap(capture_file *cfile)
{
  guint32 framenum;
  frame_data *fdata;
  Buffer buf;
  wtap_rec rec;
  int err;
  char *err_info = NULL;

  guint tap_flags;
  gboolean create_proto_tree;
  epan_dissect_t edt;
  column_info *cinfo;

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  /* If any tap listeners require the columns, construct them. */
  cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cfile->cinfo : NULL;

  /*
   * Determine whether we need to create a protocol tree.
   * We do if:
   *
   *    one of the tap listeners is going to apply a filter;
   *
   *    one of the tap listeners requires a protocol tree.
   */
  create_proto_tree =
      (have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cfile->epan, create_proto_tree, false);

  reset_tap_listeners();

  for (framenum = 1; framenum <= cfile->count; framenum++)
  {
    fdata = wg_get_frame(cfile, framenum);

    if (!wtap_seek_read(cfile->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info))
      break;

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = framenum - 1;
    epan_dissect_run_with_taps(&edt, cfile->cd_t, &rec,
                               frame_tvbuff_new_buffer(&cfile->provider, fdata, &buf),
                               fdata, cinfo);
    wtap_rec_reset(&rec);
    epan_dissect_reset(&edt);
  }

  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);
  draw_tap_listeners(true);

  return 0;
}

int wg_session_process_load(capture_file *cfile, const char *path, summary_tally *summary, char **err_ret)
{
  int ret = 0;

  if (!path)
    return 1;

  if (wg_cf_open(cfile, path, WTAP_TYPE_AUTO, FALSE, &ret) != CF_OK)
  {
    *err_ret = g_strdup_printf("Unable to open the file");
    return 1;
  }

  TRY
  {
    ret = wg_load_cap_file(cfile, summary);
  }
  CATCH(OutOfMemoryError)
  {
    *err_ret = g_strdup_printf("Load failed, out of memory");
    ret = ENOMEM;
  }
  ENDTRY;

  return ret;
}

void wg_session_filter_free(gpointer data)
{
  struct wg_filter_item *l = (struct wg_filter_item *)data;

  g_free(l->filtered);
  g_free(l);
}

vector<ProtoTree>
wg_session_process_frame_cb_tree(epan_dissect_t *edt, proto_tree *tree, tvbuff_t **tvbs, gboolean display_hidden)
{
  proto_node *node;

  vector<ProtoTree> res;

  for (node = tree->first_child; node; node = node->next)
  {
    field_info *finfo = PNODE_FINFO(node);

    if (!finfo)
      continue;

    if (!display_hidden && FI_GET_FLAG(finfo, FI_HIDDEN))
      continue;

    ProtoTree t;

    if (!finfo->rep)
    {
      char label_str[ITEM_LABEL_LENGTH];

      label_str[0] = '\0';
      proto_item_fill_label(finfo, label_str);
      t.label = string(label_str);
    }
    else
    {
      t.label = string(finfo->rep->representation);
    }

    t.data_source_idx = 0;
    if (finfo->ds_tvb && tvbs && tvbs[0] != finfo->ds_tvb)
    {
      int idx;

      for (idx = 1; tvbs[idx]; idx++)
      {
        if (tvbs[idx] == finfo->ds_tvb)
        {
          t.data_source_idx = idx;
          break;
        }
      }
    }

    t.start = 0, t.length = 0;

    if (finfo->start >= 0 && finfo->length > 0)
    {
      t.start = finfo->start, t.length = finfo->length;
    }

    if (FI_GET_FLAG(finfo, PI_SEVERITY_MASK))
    {
      t.severity = try_val_to_str(FI_GET_FLAG(finfo, PI_SEVERITY_MASK), expert_severity_vals);
    }

    if (finfo->hfinfo)
    {
      char *filter;

      if (finfo->hfinfo->type == FT_PROTOCOL)
      {
        t.type = "proto";
      }
      else if (finfo->hfinfo->type == FT_FRAMENUM)
      {
        t.type = "framenum";
        t.fnum = static_cast<unsigned int>(finfo->value.value.uinteger);
      }
      else if (FI_GET_FLAG(finfo, FI_URL) && finfo->hfinfo->type == FT_STRING)
      {
        char *url = fvalue_to_string_repr(NULL, &finfo->value, FTREPR_DISPLAY, finfo->hfinfo->display);
        t.type = "url";
        t.url = url;
        wmem_free(NULL, url);
      }

      filter = proto_construct_match_selected_string(finfo, edt);
      if (filter)
      {
        t.filter = string(filter);

        wmem_free(NULL, filter);
      }
    }

    if (((proto_tree *)node)->first_child)
    {
      vector<ProtoTree> children = wg_session_process_frame_cb_tree(edt, (proto_tree *)node, tvbs, display_hidden);
      t.tree = children;
    }

    res.push_back(t);
  }

  return res;
}

struct VisitData
{
  packet_info *pi;
  vector<vector<string>> *followArray;
};

static gboolean
wg_session_follower_visit_cb(const void *key _U_, void *value, void *user_data)
{
  register_follow_t *follower = (register_follow_t *)value;
  VisitData *visitData = (VisitData *)user_data;
  packet_info *pi = visitData->pi;
  vector<vector<string>> *followArray = visitData->followArray;

  const int proto_id = get_follow_proto_id(follower);
  guint32 ignore_stream;
  guint32 ignore_sub_stream;

  if (proto_is_frame_protocol(pi->layers, proto_get_protocol_filter_name(proto_id)))
  {
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

void wg_session_process_frame_cb(capture_file *cfile, epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data)
{
  packet_info *pi = &edt->pi;
  frame_data *fdata = pi->fd;
  wtap_block_t pkt_block = fdata->has_modified_block ? cap_file_provider_get_modified_block(&cfile->provider, fdata) : pi->rec->block;

  Frame *f = (Frame *)data;

  if (pkt_block)
  {
    guint n = wtap_block_count_option(pkt_block, OPT_COMMENT);

    for (guint i = 0; i < n; i++)
    {
      gchar *comment;
      if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, i, &comment))
      {
        f->comments.push_back(std::string(comment));
      }
    }
  }

  if (tree)
  {
    tvbuff_t **tvbs = NULL;

    /* arrayize data src, to speedup searching for ds_tvb index */
    if (data_src && data_src->next /* only needed if there are more than one data source */)
    {
      guint count = g_slist_length((GSList *)data_src);
      tvbs = (tvbuff_t **)g_malloc0((count + 1) * sizeof(*tvbs));

      for (guint i = 0; i < count; i++)
      {
        const struct data_source *src = (const struct data_source *)g_slist_nth_data((GSList *)data_src, i);

        tvbs[i] = get_data_source_tvb(src);
      }

      tvbs[count] = NULL;
    }

    vector<ProtoTree> children = wg_session_process_frame_cb_tree(edt, tree, tvbs, FALSE);
    f->tree = children;

    g_free(tvbs);
  }

  while (data_src)
  {
    struct data_source *src = (struct data_source *)data_src->data;
    tvbuff_t *tvb;
    guint length;

    tvb = get_data_source_tvb(src);
    length = tvb_captured_length(tvb);
    char *src_name = get_data_source_name(src);
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
  for (const auto &follow : *visitData.followArray)
  {
    f->follow.push_back(follow);
  }
}

Follow wg_session_process_follow(capture_file *cfile, const char *tok_follow, const char *tok_filter, char **err_ret)
{
  register_follow_t *follower;
  GString *tap_error;

  follow_info_t *follow_info;

  const char *host;
  char *port;
  Follow f;

  follower = get_follow_by_name(tok_follow);
  if (!follower)
  {
    *err_ret = g_strdup_printf("follower=%s not found", tok_follow);
    return f;
  }

  /* follow_reset_stream ? */
  follow_info = g_new0(follow_info_t, 1);
  /* gui_data, filter_out_filter not set, but not used by dissector */

  tap_error = register_tap_listener(get_follow_tap_string(follower), follow_info, tok_filter, 0, NULL, get_follow_tap_handler(follower), NULL, NULL);
  if (tap_error)
  {
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

  if (follow_info->payload)
  {
    follow_record_t *follow_record;
    GList *cur;
    for (cur = g_list_last(follow_info->payload); cur; cur = g_list_previous(cur))
    {
      follow_record = (follow_record_t *)cur->data;
      char *encoded = g_base64_encode(follow_record->data->data, follow_record->data->len);
      f.payloads.push_back(FollowPayload{int(follow_record->packet_num), string(encoded), static_cast<unsigned int>(follow_record->is_server ? 1 : 0)});
    }
  }

  remove_tap_listener(follow_info);
  follow_info_free(follow_info);
  return f;
}

void wg_session_process_frames_cb(capture_file *cfile, epan_dissect_t *edt, proto_tree *tree _U_,
                                  struct epan_column_info *cinfo, const GSList *data_src _U_, void *data)
{
  packet_info *pi = &edt->pi;
  frame_data *fdata = pi->fd;
  wtap_block_t pkt_block = NULL;
  char *comment;

  vector<FrameMeta> *store = (vector<FrameMeta> *)data;

  FrameMeta f;
  f.number = pi->num;

  for (int col = 0; col < cinfo->num_cols; ++col)
  {
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

  if (fdata->color_filter)
  {
    f.bg = color_t_to_rgb(&fdata->color_filter->bg_color);
    f.fg = color_t_to_rgb(&fdata->color_filter->fg_color);
  }

  store->push_back(f);
}

enum dissect_request_status
wg_dissect_request(capture_file *cfile, guint32 framenum, guint32 frame_ref_num,
                   guint32 prev_dis_num, wtap_rec *rec, Buffer *buf,
                   column_info *cinfo, guint32 dissect_flags,
                   wg_dissect_func_t cb, void *data,
                   int *err, gchar **err_info)
{
  frame_data *fdata;
  epan_dissect_t edt;
  gboolean create_proto_tree;

  fdata = wg_get_frame(cfile, framenum);
  if (fdata == NULL)
    return DISSECT_REQUEST_NO_SUCH_FRAME;

  if (!wtap_seek_read(cfile->provider.wth, fdata->file_off, rec, buf, err, err_info))
  {
    if (cinfo != NULL)
      col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);
    return DISSECT_REQUEST_READ_ERROR; /* error reading the record */
  }

  create_proto_tree = ((dissect_flags & WG_DISSECT_FLAG_PROTO_TREE) ||
                       ((dissect_flags & WG_DISSECT_FLAG_COLOR) && color_filters_used()) ||
                       (cinfo && have_custom_cols(cinfo)));
  epan_dissect_init(&edt, cfile->epan, create_proto_tree, (dissect_flags & WG_DISSECT_FLAG_PROTO_TREE));

  if (dissect_flags & WG_DISSECT_FLAG_COLOR)
  {
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
                   frame_tvbuff_new_buffer(&cfile->provider, fdata, buf),
                   fdata, cinfo);

  if (cinfo)
  {
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

int wg_filter(capture_file *cfile, const char *dftext, guint8 **result, guint *passed)
{
  dfilter_t *dfcode = NULL;

  guint32 framenum, prev_dis_num = 0;
  guint32 frames_count;
  Buffer buf;
  wtap_rec rec;
  int err;
  char *err_info = NULL;

  guint passed_frames = 0;
  guint8 *result_bits;
  guint8 passed_bits;

  epan_dissect_t edt;

  if (!dfilter_compile(dftext, &dfcode, &err_info))
  {
    g_free(err_info);
    return -1;
  }

  /* if dfilter_compile() success, but (dfcode == NULL) all frames are matching */
  if (dfcode == NULL)
  {
    *result = NULL;
    *passed = cfile->count;
    return 0;
  }

  frames_count = cfile->count;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cfile->epan, TRUE, FALSE);

  passed_bits = 0;
  result_bits = (guint8 *)g_malloc(2 + (frames_count / 8));

  for (framenum = 1; framenum <= frames_count; framenum++)
  {
    frame_data *fdata = wg_get_frame(cfile, framenum);

    if ((framenum & 7) == 0)
    {
      result_bits[(framenum / 8) - 1] = passed_bits;
      passed_bits = 0;
    }

    if (!wtap_seek_read(cfile->provider.wth, fdata->file_off, &rec, &buf, &err, &err_info))
      break;

    /* frame_data_set_before_dissect */
    epan_dissect_prime_with_dfilter(&edt, dfcode);

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = prev_dis_num;
    epan_dissect_run(&edt, cfile->cd_t, &rec,
                     frame_tvbuff_new_buffer(&cfile->provider, fdata, &buf),
                     fdata, NULL);

    if (dfilter_apply_edt(dfcode, &edt))
    {
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
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  dfilter_free(dfcode);

  *result = result_bits;
  *passed = passed_frames;

  return framenum;
}

const struct wg_filter_item *
session_filter_data(GHashTable *filter_table, capture_file *cfile, const char *filter)
{
  struct wg_filter_item *l;

  l = (struct wg_filter_item *)g_hash_table_lookup(filter_table, filter);
  if (!l)
  {
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

Frame wg_process_frame(capture_file *cfile, guint32 framenum, char **err_ret)
{
  column_info *cinfo = NULL;

  guint32 ref_frame_num, prev_dis_num;
  guint32 dissect_flags = WG_DISSECT_FLAG_NULL;
  wtap_rec rec;   /* Record metadata */
  Buffer rec_buf; /* Record data */
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

  wtap_rec_init(&rec);
  ws_buffer_init(&rec_buf, 1514);

  Frame f;
  f.number = framenum;

  status = wg_dissect_request(cfile, framenum, ref_frame_num, prev_dis_num,
                              &rec, &rec_buf, cinfo, dissect_flags,
                              &wg_session_process_frame_cb, &f, &err, &err_info);
  switch (status)
  {

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
  ws_buffer_free(&rec_buf);

  return f;
}

FramesResponse wg_process_frames(capture_file *cfile, GHashTable *filter_table, const char *filter, guint32 skip, guint32 limit, char **err_ret)
{
  const guint8 *filter_data = NULL;

  wtap_rec rec;   /* Record metadata */
  Buffer rec_buf; /* Record data */
  column_info *cinfo = &cfile->cinfo;

  FramesResponse result;
  result.matched = 0;

  vector<FrameMeta> res;

  const struct wg_filter_item *filter_item;

  filter_item = session_filter_data(filter_table, cfile, filter);
  if (!filter_item)
  {
    *err_ret = g_strdup_printf("Filter expression invalid");
    return result;
  }

  filter_data = filter_item->filtered;

  wtap_rec_init(&rec);
  ws_buffer_init(&rec_buf, 1514);

  for (guint32 framenum = 1; framenum <= cfile->count; framenum++)
  {
    frame_data *fdata;
    enum dissect_request_status status;
    int err;
    gchar *err_info;

    if (filter_data && !(filter_data[framenum / 8] & (1 << (framenum % 8))))
      continue;

    if (skip)
    {
      skip--;
      continue;
    }

    fdata = wg_get_frame(cfile, framenum);
    status = wg_dissect_request(cfile, framenum,
                                (framenum != 1) ? 1 : 0, framenum - 1,
                                &rec, &rec_buf, cinfo,
                                (fdata->color_filter == NULL) ? WG_DISSECT_FLAG_COLOR : WG_DISSECT_FLAG_NULL,
                                &wg_session_process_frames_cb, &res,
                                &err, &err_info);
    switch (status)
    {

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
  ws_buffer_free(&rec_buf);

  result.matched = filter_item->passed;
  result.frames = res;

  return result;
}

Follow wg_process_follow(capture_file *cfile, const char *follow, const char *filter, char **err_ret)
{
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
 *   field - array of object with attributes:
 *         field - field text
 *         type - field type (FT_ number)
 *         name - field name
 */
vector<CompleteField>
wg_session_process_complete(const char *tok_field)
{
  vector<CompleteField> res;
  if (tok_field != NULL && tok_field[0])
  {
    const size_t filter_length = strlen(tok_field);
    const int filter_with_dot = !!strchr(tok_field, '.');

    void *proto_cookie;
    void *field_cookie;
    int proto_id;

    for (proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie))
    {
      protocol_t *protocol = find_protocol_by_id(proto_id);
      const char *protocol_filter;
      const char *protocol_name;
      header_field_info *hfinfo;

      if (!proto_is_protocol_enabled(protocol))
        continue;

      protocol_name = proto_get_protocol_long_name(protocol);
      protocol_filter = proto_get_protocol_filter_name(proto_id);

      if (strlen(protocol_filter) >= filter_length && !g_ascii_strncasecmp(tok_field, protocol_filter, filter_length))
      {
        res.push_back(CompleteField{string(protocol_filter), static_cast<int>(FT_PROTOCOL), string(protocol_name)});
      }

      if (!filter_with_dot)
        continue;

      for (hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie))
      {
        if (hfinfo->same_name_prev_id != -1) /* ignore duplicate names */
          continue;

        if (strlen(hfinfo->abbrev) >= filter_length && !g_ascii_strncasecmp(tok_field, hfinfo->abbrev, filter_length))
        {
          CompleteField f;
          {
            f.field = string(hfinfo->abbrev);
            /* XXX, skip displaying name, if there are multiple (to not confuse user) */
            if (hfinfo->same_name_next == NULL)
            {
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

static struct wg_export_object_list *
wg_eo_object_list_get_entry_by_type(void *gui_data, const char *tap_type)
{
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)gui_data;
  for (; object_list; object_list = object_list->next)
  {
    if (!strcmp(object_list->type, tap_type))
      return object_list;
  }
  return NULL;
}

static export_object_entry_t *
wg_eo_object_list_get_entry(void *gui_data, int row)
{
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)gui_data;

  return (export_object_entry_t *)g_slist_nth_data(object_list->entries, row);
}

static void
wg_eo_object_list_add_entry(void *gui_data, export_object_entry_t *entry)
{
  struct wg_export_object_list *object_list = (struct wg_export_object_list *)gui_data;

  object_list->entries = g_slist_append(object_list->entries, entry);
}

static GString *wg_session_eo_register_tap_listener(register_eo_t *eo, const char *tap_type, const char *tap_filter, tap_draw_cb tap_draw, void **ptap_data, GFreeFunc *ptap_free)
{
  export_object_list_t *eo_object;
  struct wg_export_object_list *object_list;

  object_list = wg_eo_object_list_get_entry_by_type(wg_eo_list, tap_type);
  if (object_list)
  {
    g_slist_free_full(object_list->entries, (GDestroyNotify)eo_free_entry);
    object_list->entries = NULL;
  }
  else
  {
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
  *ptap_free = g_free; /* need to free only eo_object, object_list need to be kept for potential download */

  return register_tap_listener(get_eo_tap_listener_name(eo), eo_object, tap_filter, 0, NULL, get_eo_packet_func(eo), tap_draw, NULL);
}

gboolean wg_session_eo_retap_listener(capture_file *cfile, const char *tap_type, char **err_ret)
{
  gboolean ok = TRUE;
  register_eo_t *eo = NULL;
  GString *tap_error = NULL;
  void *tap_data = NULL;
  GFreeFunc tap_free = NULL;

  // get <name> from eo:<name>, get_eo_by_name only needs the name (http etc.)
  eo = get_eo_by_name(tap_type + 3);
  if (!eo)
  {
    ok = FALSE;
    *err_ret = g_strdup_printf("eo=%s not found", tap_type + 3);
  }

  if (ok)
  {
    tap_error = wg_session_eo_register_tap_listener(eo, tap_type, NULL, NULL, &tap_data, &tap_free);
    if (tap_error)
    {
      ok = FALSE;
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
 * wg_session_process_download()
 *
 * Process download request
 *
 * Input:
 *   (m) token  - token to download
 *
 * Output object with attributes:
 *   (o) file - suggested name of file
 *   (o) mime - suggested content type
 *   (o) data - payload base64 encoded
 */
DownloadFile wg_session_process_download(capture_file *cfile, const char *tok_token, char **err_ret)
{
  DownloadFile f;
  if (!tok_token)
  {
    *err_ret = g_strdup_printf("missing token");
    return f;
  }

  if (!strncmp(tok_token, "eo:", 3))
  {
    // get eo:<name> from eo:<name>_<row>
    char *tap_type = g_strdup(tok_token);
    char *tmp = strrchr(tap_type, '_');
    if (tmp)
      *tmp = '\0';

    // if eo:<name> not in wg_eo_list, retap
    if (!wg_eo_object_list_get_entry_by_type(wg_eo_list, tap_type) &&
        !wg_session_eo_retap_listener(cfile, tap_type, err_ret))
    {
      g_free(tap_type);
      *err_ret = g_strdup_printf("invalid token");
      return f;
    }

    g_free(tap_type);

    struct wg_export_object_list *object_list;
    const export_object_entry_t *eo_entry = NULL;

    for (object_list = wg_eo_list; object_list; object_list = object_list->next)
    {
      size_t eo_type_len = strlen(object_list->type);

      if (!strncmp(tok_token, object_list->type, eo_type_len) && tok_token[eo_type_len] == '_')
      {
        int row;

        if (sscanf(&tok_token[eo_type_len + 1], "%d", &row) != 1)
          break;

        eo_entry = (export_object_entry_t *)g_slist_nth_data(object_list->entries, row);
        break;
      }
    }

    if (eo_entry)
    {
      const char *mime = (eo_entry->content_type) ? eo_entry->content_type : "application/octet-stream";
      const char *filename = (eo_entry->filename) ? eo_entry->filename : tok_token;
      f.file = filename;
      f.mime = mime;
      f.data = g_base64_encode(eo_entry->payload_data, eo_entry->payload_len);
    }
    return f;
  }
  else if (!strcmp(tok_token, "ssl-secrets"))
  {
    *err_ret = g_strdup_printf("ssl-secrets download is not supported");
    return f;
    // gsize str_len;
    // char *str = ssl_export_sessions(&str_len);

    // if (str)
    // {
    //     const char *mime     = "text/plain";
    //     const char *filename = "keylog.txt";
    //   f.file = filename;
    //   f.mime = mime;
    //   f.data = g_base64_encode(str, str_len);
    // }
    // g_free(str);
    // return f;
  }
  else if (!strncmp(tok_token, "rtp:", 4))
  {
    *err_ret = g_strdup_printf("rtp download is not supported");
    return f;
    // struct wg_download_rtp rtp_req;
    // GString *tap_error;

    // memset(&rtp_req, 0, sizeof(rtp_req));
    // if (!wg_rtp_match_init(&rtp_req.id, tok_token + 4))
    // {
    // // @FIXME:
    //     sharkd_json_error(
    //             rpcid, -10001, NULL,
    //             "sharkd_session_process_download() rtp tokenizing error %s", tok_token
    //             );
    //     return;
    // }

    // tap_error = register_tap_listener("rtp", &rtp_req, NULL, 0, NULL, wg_session_packet_download_tap_rtp_cb, NULL, NULL);
    // if (tap_error)
    // {
    // // @FIXME:
    //     sharkd_json_error(
    //             rpcid, -10002, NULL,
    //             "sharkd_session_process_download() rtp error %s", tap_error->str
    //             );
    //     g_string_free(tap_error, TRUE);
    //     return;
    // }

    // wg_retap();
    // remove_tap_listener(&rtp_req);

    // if (rtp_req.packets)
    // {
    //     const char *mime     = "audio/x-wav";
    //     const char *filename = tok_token;

    // // @FIXME:
    //     f.file = filename;
    //     f.mime = mime;
    //     f.data = g_base64_encode(rtp_req.payload_data->data, rtp_req.payload_data->len);

    //     json_dumper_begin_base64(&dumper);
    // // @FIXME:
    //     wg_rtp_download_decode(&rtp_req);
    //     json_dumper_end_base64(&dumper);

    // // @FIXME:
    //     sharkd_json_result_epilogue();

    //     g_slist_free_full(rtp_req.packets, wg_rtp_download_free_items);
    // }
    // else
    // {

    // // @FIXME:
    //     sharkd_json_error(
    //         rpcid, -10003, NULL,
    //         "no rtp data available"
    //     );
    // }
  }
  else
  {
    *err_ret = g_strdup_printf("unrecognized token");
    return f;
  }
}

// static gboolean wg_rtp_match_init(rtpstream_id_t *id, const char *init_str)
// {
//     gboolean ret = FALSE;
//     char **arr;
//     guint32 tmp_addr_src, tmp_addr_dst;
//     address tmp_src_addr, tmp_dst_addr;

//     memset(id, 0, sizeof(*id));

//     arr = g_strsplit(init_str, "_", 7); /* pass larger value, so we'll catch incorrect input :) */
//     if (g_strv_length(arr) != 5)
//         goto fail;

//     /* TODO, for now only IPv4 */
//     if (!get_host_ipaddr(arr[0], &tmp_addr_src))
//         goto fail;

//     if (!ws_strtou16(arr[1], NULL, &id->src_port))
//         goto fail;

//     if (!get_host_ipaddr(arr[2], &tmp_addr_dst))
//         goto fail;

//     if (!ws_strtou16(arr[3], NULL, &id->dst_port))
//         goto fail;

//     if (!ws_hexstrtou32(arr[4], NULL, &id->ssrc))
//         goto fail;

//     set_address(&tmp_src_addr, AT_IPv4, 4, &tmp_addr_src);
//     copy_address(&id->src_addr, &tmp_src_addr);
//     set_address(&tmp_dst_addr, AT_IPv4, 4, &tmp_addr_dst);
//     copy_address(&id->dst_addr, &tmp_dst_addr);

//     ret = TRUE;

// fail:
//     g_strfreev(arr);
//     return ret;
// }

// static tap_packet_status wg_session_packet_download_tap_rtp_cb(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
// {
//     const struct _rtp_info *rtp_info = (const struct _rtp_info *) data;
//     struct sharkd_download_rtp *req_rtp = (struct sharkd_download_rtp *) tapdata;

//     /* do not consider RTP packets without a setup frame */
//     if (rtp_info->info_setup_frame_num == 0)
//         return TAP_PACKET_DONT_REDRAW;

//     if (rtpstream_id_equal_pinfo_rtp_info(&req_rtp->id, pinfo, rtp_info))
//     {
//         rtp_packet_t *rtp_packet;

//         rtp_packet = g_new0(rtp_packet_t, 1);
//         rtp_packet->info = (struct _rtp_info *) g_memdup2(rtp_info, sizeof(struct _rtp_info));

//         if (rtp_info->info_all_data_present && rtp_info->info_payload_len != 0)
//             rtp_packet->payload_data = (guint8 *) g_memdup2(&(rtp_info->info_data[rtp_info->info_payload_offset]), rtp_info->info_payload_len);

//         if (!req_rtp->packets)
//             req_rtp->start_time = nstime_to_sec(&pinfo->abs_ts);

//         rtp_packet->frame_num = pinfo->num;
//         rtp_packet->arrive_offset = nstime_to_sec(&pinfo->abs_ts) - req_rtp->start_time;

//         /* XXX, O(n) optimize */
//         req_rtp->packets = g_slist_append(req_rtp->packets, rtp_packet);
//     }

//     return TAP_PACKET_DONT_REDRAW;
// }

// static void wg_rtp_download_free_items(void *ptr)
// {
//     rtp_packet_t *rtp_packet = (rtp_packet_t *) ptr;

//     g_free(rtp_packet->info);
//     g_free(rtp_packet->payload_data);
//     g_free(rtp_packet);
// }

// static void wg_rtp_download_decode(struct wg_download_rtp *req)
// {
//     /* based on RtpAudioStream::decode() 6e29d874f8b5e6ebc59f661a0bb0dab8e56f122a */
//     /* TODO, for now only without silence (timing_mode_ = Uninterrupted) */

//     static const int sample_bytes_ = sizeof(SAMPLE) / sizeof(char);

//     guint32 audio_out_rate_ = 0;
//     struct _GHashTable *decoders_hash_ = rtp_decoder_hash_table_new();
//     struct SpeexResamplerState_ *audio_resampler_ = NULL;

//     gsize resample_buff_len = 0x1000;
//     SAMPLE *resample_buff = (SAMPLE *) g_malloc(resample_buff_len);
//     spx_uint32_t cur_in_rate = 0;
//     char *write_buff = NULL;
//     size_t write_bytes = 0;
//     unsigned channels = 0;
//     unsigned sample_rate = 0;

//     GSList *l;

//     for (l = req->packets; l; l = l->next)
//     {
//         rtp_packet_t *rtp_packet = (rtp_packet_t *) l->data;

//         SAMPLE *decode_buff = NULL;
//         size_t decoded_bytes;

//         decoded_bytes = decode_rtp_packet(rtp_packet, &decode_buff, decoders_hash_, &channels, &sample_rate);
//         if (decoded_bytes == 0 || sample_rate == 0)
//         {
//             /* We didn't decode anything. Clean up and prep for the next packet. */
//             g_free(decode_buff);
//             continue;
//         }

//         if (audio_out_rate_ == 0)
//         {
//             guint32 tmp32;
//             guint16 tmp16;
//             char wav_hdr[44];

//             /* First non-zero wins */
//             audio_out_rate_ = sample_rate;

//             RTP_STREAM_DEBUG("Audio sample rate is %u", audio_out_rate_);

//             /* write WAVE header */
//             memset(&wav_hdr, 0, sizeof(wav_hdr));
//             memcpy(&wav_hdr[0], "RIFF", 4);
//             memcpy(&wav_hdr[4], "\xFF\xFF\xFF\xFF", 4); /* XXX, unknown */
//             memcpy(&wav_hdr[8], "WAVE", 4);

//             memcpy(&wav_hdr[12], "fmt ", 4);
//             memcpy(&wav_hdr[16], "\x10\x00\x00\x00", 4); /* PCM */
//             memcpy(&wav_hdr[20], "\x01\x00", 2);         /* PCM */
//             /* # channels */
//             tmp16 = channels;
//             memcpy(&wav_hdr[22], &tmp16, 2);
//             /* sample rate */
//             tmp32 = sample_rate;
//             memcpy(&wav_hdr[24], &tmp32, 4);
//             /* byte rate */
//             tmp32 = sample_rate * channels * sample_bytes_;
//             memcpy(&wav_hdr[28], &tmp32, 4);
//             /* block align */
//             tmp16 = channels * sample_bytes_;
//             memcpy(&wav_hdr[32], &tmp16, 2);
//             /* bits per sample */
//             tmp16 = 8 * sample_bytes_;
//             memcpy(&wav_hdr[34], &tmp16, 2);

//             memcpy(&wav_hdr[36], "data", 4);
//             memcpy(&wav_hdr[40], "\xFF\xFF\xFF\xFF", 4); /* XXX, unknown */

// // @FIXME:
//             json_dumper_write_base64(&dumper, wav_hdr, sizeof(wav_hdr));
//         }

//         // Write samples to our file.
//         write_buff = (char *) decode_buff;
//         write_bytes = decoded_bytes;

//         if (audio_out_rate_ != sample_rate)
//         {
//             spx_uint32_t in_len, out_len;

//             /* Resample the audio to match our previous output rate. */
//             if (!audio_resampler_)
//             {
//                 audio_resampler_ = speex_resampler_init(1, sample_rate, audio_out_rate_, 10, NULL);
//                 speex_resampler_skip_zeros(audio_resampler_);
//                 RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, audio_out_rate_);
//             }
//             else
//             {
//                 spx_uint32_t audio_out_rate;
//                 speex_resampler_get_rate(audio_resampler_, &cur_in_rate, &audio_out_rate);

//                 if (sample_rate != cur_in_rate)
//                 {
//                     speex_resampler_set_rate(audio_resampler_, sample_rate, audio_out_rate);
//                     RTP_STREAM_DEBUG("Changed input rate from %u to %u Hz. Out is %u.", cur_in_rate, sample_rate, audio_out_rate_);
//                 }
//             }
//             in_len = (spx_uint32_t)rtp_packet->info->info_payload_len;
//             out_len = (audio_out_rate_ * (spx_uint32_t)rtp_packet->info->info_payload_len / sample_rate) + (audio_out_rate_ % sample_rate != 0);
//             if (out_len * sample_bytes_ > resample_buff_len)
//             {
//                 while ((out_len * sample_bytes_ > resample_buff_len))
//                     resample_buff_len *= 2;
//                 resample_buff = (SAMPLE *) g_realloc(resample_buff, resample_buff_len);
//             }

//             speex_resampler_process_int(audio_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
//             write_buff = (char *) resample_buff;
//             write_bytes = out_len * sample_bytes_;
//         }

//         /* Write the decoded, possibly-resampled audio */
//         // @FIXME:
//         json_dumper_write_base64(&dumper, write_buff, write_bytes);

//         g_free(decode_buff);
//     }

//     g_free(resample_buff);
//     g_hash_table_destroy(decoders_hash_);
// }
