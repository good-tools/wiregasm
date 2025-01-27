#include "lib.h"
#include "wiregasm.h"

// #include <epan/sequence_analysis.h>
// #include <ui/io_graph_item.h>

#include <epan/stats_tree_priv.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/expert.h>
#include <epan/export_object.h>
#include <epan/follow.h>
#include <epan/rtd_table.h>
#include <epan/srt_table.h>

static guint32 cum_bytes;
static frame_data ref_frame;

struct sharkd_hosts_req
{
  const char *tap_name;
  gboolean dump_v4;
  gboolean dump_v6;
};

struct sharkd_expert_tap
{
  GSList *details;
  GStringChunk *text;
};

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
      const uint32_t pkt_num = eo_entry->pkt_num;
      const size_t payload_len = eo_entry->payload_len;
      const char *hostname = eo_entry->hostname;
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

// /**
//  * wg_session_process_tap_flow_cb()
//  *
//  * Output flow tap:
//  *   (m) tap         - tap name
//  *   (m) type:flow   - tap output type
//  *   (m) nodes       - array of strings with node address
//  *   (m) flows       - array of object with attributes:
//  *                  (m) t  - frame time string
//  *                  (m) n  - array of two numbers with source node index and destination node index
//  *                  (m) pn - array of two numbers with source and destination port
//  *                  (o) c  - comment
//  */
// static void
// wg_session_process_tap_flow_cb(void *tapdata)
// {
//     seq_analysis_info_t *graph_analysis = (seq_analysis_info_t *) tapdata;
//     GList *flow_list;
//     guint i;

//     sequence_analysis_get_nodes(graph_analysis);

//     json_dumper_begin_object(&dumper);
//     sharkd_json_value_stringf("tap", "seqa:%s", graph_analysis->name);
//     sharkd_json_value_string("type", "flow");

//     sharkd_json_array_open("nodes");
//     for (i = 0; i < graph_analysis->num_nodes; i++)
//     {
//         char *addr_str;

//         addr_str = address_to_display(NULL, &(graph_analysis->nodes[i]));
//         sharkd_json_value_string(NULL, addr_str);
//         wmem_free(NULL, addr_str);
//     }
//     sharkd_json_array_close();

//     sharkd_json_array_open("flows");
//     flow_list = g_queue_peek_nth_link(graph_analysis->items, 0);
//     while (flow_list)
//     {
//         seq_analysis_item_t *sai = (seq_analysis_item_t *) flow_list->data;

//         flow_list = g_list_next(flow_list);

//         if (!sai->display)
//             continue;

//         json_dumper_begin_object(&dumper);

//         sharkd_json_value_string("t", sai->time_str);
//         sharkd_json_value_anyf("n", "[%u,%u]", sai->src_node, sai->dst_node);
//         sharkd_json_value_anyf("pn", "[%u,%u]", sai->port_src, sai->port_dst);

//         if (sai->comment)
//             sharkd_json_value_string("c", sai->comment);

//         json_dumper_end_object(&dumper);
//     }
//     sharkd_json_array_close();

//     json_dumper_end_object(&dumper);
// }

// static void
// wg_session_free_tap_flow_cb(void *tapdata)
// {
//     seq_analysis_info_t *graph_analysis = (seq_analysis_info_t *) tapdata;

//     sequence_analysis_info_free(graph_analysis);
// }

static void
sharkd_session_free_tap_stats_cb(void *psp)
{
  stats_tree *st = (stats_tree *)psp;

  stats_tree_free(st);
}
static void
sharkd_session_process_tap_stats_node_cb(const stat_node *n)
{
  stat_node *node;

  sharkd_json_array_open(NULL);
  for (node = n->children; node; node = node->next)
  {
    json_dumper_begin_object(&dumper);

    /* code based on stats_tree_get_values_from_node() */
    sharkd_json_value_string("name", node->name);
    sharkd_json_value_anyf("count", "%d", node->counter);
    if (node->counter && ((node->st_flags & ST_FLG_AVERAGE) || node->rng))
    {
      switch (node->datatype)
      {
      case STAT_DT_INT:
        sharkd_json_value_anyf("avg", "%.2f", ((float)node->total.int_total) / node->counter);
        sharkd_json_value_anyf("min", "%d", node->minvalue.int_min);
        sharkd_json_value_anyf("max", "%d", node->maxvalue.int_max);
        break;
      case STAT_DT_FLOAT:
        sharkd_json_value_anyf("avg", "%.2f", node->total.float_total / node->counter);
        sharkd_json_value_anyf("min", "%f", node->minvalue.float_min);
        sharkd_json_value_anyf("max", "%f", node->maxvalue.float_max);
        break;
      }
    }

    if (node->st->elapsed)
      sharkd_json_value_anyf("rate", "%.4f", ((float)node->counter) / node->st->elapsed);

    if (node->parent && node->parent->counter)
      sharkd_json_value_anyf("perc", "%.2f", (node->counter * 100.0) / node->parent->counter);
    else if (node->parent == &(node->st->root))
      sharkd_json_value_anyf("perc", "100");

    if (prefs.st_enable_burstinfo && node->max_burst)
    {
      if (prefs.st_burst_showcount)
        sharkd_json_value_anyf("burstcount", "%d", node->max_burst);
      else
        sharkd_json_value_anyf("burstrate", "%.4f", ((double)node->max_burst) / prefs.st_burst_windowlen);

      sharkd_json_value_anyf("bursttime", "%.3f", (node->burst_time / 1000.0));
    }

    if (node->children)
    {
      sharkd_json_value_anyf("sub", NULL);
      sharkd_session_process_tap_stats_node_cb(node);
    }
    json_dumper_end_object(&dumper);
  }
  sharkd_json_array_close();
}

/**
 * wg_session_process_tap_stats_cb()
 *
 * Output stats tap:
 *
 *   (m) tap        - tap name
 *   (m) type:stats - tap output type
 *   (m) name       - stat name
 *   (m) stats      - array of object with attributes:
 *                  (m) name       - stat item name
 *                  (m) count      - stat item counter
 *                  (o) avg        - stat item averange value
 *                  (o) min        - stat item min value
 *                  (o) max        - stat item max value
 *                  (o) rate       - stat item rate value (ms)
 *                  (o) perc       - stat item percentage
 *                  (o) burstrate  - stat item burst rate
 *                  (o) burstcount - stat item burst count
 *                  (o) burstttme  - stat item burst start
 *                  (o) sub        - array of object with attributes like in stats node.
 */
static void
wg_session_process_tap_stats_cb(void *psp)
{
  stats_tree *st = (stats_tree *)psp;

  json_dumper_begin_object(&dumper);

  sharkd_json_value_stringf("tap", "stats:%s", st->cfg->abbr);
  sharkd_json_value_string("type", "stats");
  sharkd_json_value_string("name", st->cfg->name);

  sharkd_json_value_anyf("stats", NULL);
  sharkd_session_process_tap_stats_node_cb(&st->root);

  json_dumper_end_object(&dumper);
}

static tap_packet_status
wg_session_packet_tap_expert_cb(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer, tap_flags_t flags _U_)
{
  struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *)tapdata;
  const expert_info_t *ei = (const expert_info_t *)pointer;
  expert_info_t *ei_copy;

  if (ei == NULL)
    return TAP_PACKET_DONT_REDRAW;

  ei_copy = g_new(expert_info_t, 1);
  /* Note: this is a shallow copy */
  *ei_copy = *ei;

  /* ei->protocol, ei->summary might be allocated in packet scope, make a copy. */
  ei_copy->protocol = g_string_chunk_insert_const(etd->text, ei_copy->protocol);
  ei_copy->summary = g_string_chunk_insert_const(etd->text, ei_copy->summary);

  etd->details = g_slist_prepend(etd->details, ei_copy);

  return TAP_PACKET_REDRAW;
}

/**
 * sharkd_session_process_tap_nstat_cb()
 *
 * Output nstat tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) fields: array of objects with attributes:
 *                  (m) c - name
 *
 *   (m) tables: array of object with attributes:
 *                  (m) t - table title
 *                  (m) i - array of items
 */
static void
sharkd_session_process_tap_nstat_cb(void *arg)
{
  stat_data_t *stat_data = (stat_data_t *)arg;
  guint i, j, k;

  json_dumper_begin_object(&dumper);
  sharkd_json_value_stringf("tap", "nstat:%s", stat_data->stat_tap_data->cli_string);
  sharkd_json_value_string("type", "nstat");

  sharkd_json_array_open("fields");
  for (i = 0; i < stat_data->stat_tap_data->nfields; i++)
  {
    stat_tap_table_item *field = &(stat_data->stat_tap_data->fields[i]);

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("c", field->column_name);
    json_dumper_end_object(&dumper);
  }
  sharkd_json_array_close();

  sharkd_json_array_open("tables");
  for (i = 0; i < stat_data->stat_tap_data->tables->len; i++)
  {
    stat_tap_table *table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table *, i);

    json_dumper_begin_object(&dumper);

    sharkd_json_value_string("t", table->title);

    sharkd_json_array_open("i");
    for (j = 0; j < table->num_elements; j++)
    {
      stat_tap_table_item_type *field_data;

      field_data = stat_tap_get_field_data(table, j, 0);
      if (field_data == NULL || field_data->type == TABLE_ITEM_NONE) /* Nothing for us here */
        continue;

      sharkd_json_array_open(NULL);
      for (k = 0; k < table->num_fields; k++)
      {
        field_data = stat_tap_get_field_data(table, j, k);

        switch (field_data->type)
        {
        case TABLE_ITEM_UINT:
          sharkd_json_value_anyf(NULL, "%u", field_data->value.uint_value);
          break;

        case TABLE_ITEM_INT:
          sharkd_json_value_anyf(NULL, "%d", field_data->value.int_value);
          break;

        case TABLE_ITEM_STRING:
          sharkd_json_value_string(NULL, field_data->value.string_value);
          break;

        case TABLE_ITEM_FLOAT:
          sharkd_json_value_anyf(NULL, "%f", field_data->value.float_value);
          break;

        case TABLE_ITEM_ENUM:
          sharkd_json_value_anyf(NULL, "%d", field_data->value.enum_value);
          break;

        case TABLE_ITEM_NONE:
          sharkd_json_value_anyf(NULL, "null");
          break;
        }
      }

      sharkd_json_array_close();
    }
    sharkd_json_array_close();
    json_dumper_end_object(&dumper);
  }
  sharkd_json_array_close();

  json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_nstat_cb(void *arg)
{
  stat_data_t *stat_data = (stat_data_t *)arg;

  free_stat_tables(stat_data->stat_tap_data);
}

static void
wg_session_free_tap_expert_cb(void *tapdata)
{
  struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *)tapdata;

  g_slist_free_full(etd->details, g_free);
  g_string_chunk_free(etd->text);
  g_free(etd);
}

/**
 * sharkd_session_process_tap_eo_cb()
 *
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
static void
wg_session_process_tap_eo_cb(void *tapdata)
{
  export_object_list_t *tap_object = (export_object_list_t *)tapdata;
  struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list *)tap_object->gui_data;
  GSList *slist;
  int i = 0;

  json_dumper_begin_object(&dumper);
  sharkd_json_value_string("tap", object_list->type);
  sharkd_json_value_string("type", "eo");

  sharkd_json_value_string("proto", object_list->proto);

  sharkd_json_array_open("objects");
  for (slist = object_list->entries; slist; slist = slist->next)
  {
    const export_object_entry_t *eo_entry = (export_object_entry_t *)slist->data;

    json_dumper_begin_object(&dumper);

    sharkd_json_value_anyf("pkt", "%u", eo_entry->pkt_num);

    if (eo_entry->hostname)
      sharkd_json_value_string("hostname", eo_entry->hostname);

    if (eo_entry->content_type)
      sharkd_json_value_string("type", eo_entry->content_type);

    if (eo_entry->filename)
      sharkd_json_value_string("filename", eo_entry->filename);

    sharkd_json_value_stringf("_download", "%s_%d", object_list->type, i);

    sharkd_json_value_anyf("len", "%zu", eo_entry->payload_len);

    json_dumper_end_object(&dumper);

    i++;
  }
  sharkd_json_array_close();

  json_dumper_end_object(&dumper);
}

/**
 * wg_session_process_tap()
 *
 * Process tap request
 *
 * Input:
 *   (m) tap0         - First tap request
 *   (o) tap1...tap15 - Other tap requests
 *
 * Output object with attributes:
 *   (m) taps  - array of object with attributes:
 *                  (m) tap  - tap name
 *                  (m) type - tap output type
 *                  ...
 *                  for type:stats see wg_session_process_tap_stats_cb()
 *                  for type:nstat see sharkd_session_process_tap_nstat_cb()
 *                  for type:conv see sharkd_session_process_tap_conv_cb()
 *                  for type:host see sharkd_session_process_tap_conv_cb()
 *                  for type:rtp-streams see sharkd_session_process_tap_rtp_cb()
 *                  for type:rtp-analyse see sharkd_session_process_tap_rtp_analyse_cb()
 *                  for type:eo see wg_session_process_tap_eo_cb()
 *                  for type:expert see sharkd_session_process_tap_expert_cb()
 *                  for type:rtd see sharkd_session_process_tap_rtd_cb()
 *                  for type:srt see sharkd_session_process_tap_srt_cb()
 *                  for type:flow see wg_session_process_tap_flow_cb()
 *
 *   (m) err   - error code
 */
void wg_session_process_tap(capture_file *cfile,
                            char *buf, const jsmntok_t *tokens, int count, char **err_ret)
{
  void *taps_data[16];
  GFreeFunc taps_free[16];
  int taps_count = 0;
  int i;
  const char *tap_filter = json_find_attr(buf, tokens, count, "filter");

  // rtpstream_tapinfo_t rtp_tapinfo =
  // { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, FALSE, FALSE};

  for (i = 0; i < 16; i++)
  {
    char tapbuf[32];
    const char *tok_tap;

    void *tap_data = NULL;
    GFreeFunc tap_free = NULL;
    GString *tap_error = NULL;

    snprintf(tapbuf, sizeof(tapbuf), "tap%d", i);
    tok_tap = json_find_attr(buf, tokens, count, tapbuf);
    if (!tok_tap)
      break;

    if (!strncmp(tok_tap, "stat:", 5))
    {
      stats_tree_cfg *cfg = stats_tree_get_cfg_by_abbr(tok_tap + 5);
      stats_tree *st;

      if (!cfg)
      {
        *err_ret = g_strdup_printf("stat %s not found", tok_tap + 5);
        return;
      }

      st = stats_tree_new(cfg, NULL, tap_filter);

      tap_error = register_tap_listener(st->cfg->tapname, st, st->filter, st->cfg->flags, stats_tree_reset, stats_tree_packet, wg_session_process_tap_stats_cb, NULL);

      if (!tap_error && cfg->init)
        cfg->init(st);

      tap_data = st;
      tap_free = sharkd_session_free_tap_stats_cb;
    }
    else if (!strcmp(tok_tap, "expert"))
    {
      struct sharkd_expert_tap *expert_tap;

      expert_tap = g_new0(struct sharkd_expert_tap, 1);
      expert_tap->text = g_string_chunk_new(100);

      tap_error = register_tap_listener("expert", expert_tap, tap_filter, 0, NULL, wg_session_packet_tap_expert_cb, sharkd_session_process_tap_expert_cb, NULL);

      tap_data = expert_tap;
      tap_free = wg_session_free_tap_expert_cb;
    }
    else if (!strncmp(tok_tap, "seqa:", 5))
    {
      // seq_analysis_info_t *graph_analysis;
      // register_analysis_t *analysis;
      // const char *tap_name;
      // tap_packet_cb tap_func;
      // guint tap_flags;

      // analysis = sequence_analysis_find_by_name(tok_tap + 5);
      // if (!analysis)
      // {
      //     *err_ret = g_strdup_printf("seq analysis %s not found", tok_tap + 5);
      //     return;
      // }

      // graph_analysis = sequence_analysis_info_new();
      // graph_analysis->name = tok_tap + 5;
      // /* TODO, make configurable */
      // graph_analysis->any_addr = FALSE;

      // tap_name  = sequence_analysis_get_tap_listener_name(analysis);
      // tap_flags = sequence_analysis_get_tap_flags(analysis);
      // tap_func  = sequence_analysis_get_packet_func(analysis);

      // tap_error = register_tap_listener(tap_name, graph_analysis, tap_filter, tap_flags, NULL, tap_func, wg_session_process_tap_flow_cb, NULL);

      // tap_data = graph_analysis;
      // tap_free = wg_session_free_tap_flow_cb;
    }
    else if (!strncmp(tok_tap, "conv:", 5) || !strncmp(tok_tap, "endpt:", 6))
    {
      struct register_ct *ct = NULL;
      const char *ct_tapname;
      struct sharkd_conv_tap_data *ct_data;
      tap_packet_cb tap_func = NULL;

      if (!strncmp(tok_tap, "conv:", 5))
      {
        ct = get_conversation_by_proto_id(proto_get_id_by_short_name(tok_tap + 5));

        if (!ct || !(tap_func = get_conversation_packet_func(ct)))
        {
          *err_ret = g_strdup_printf("conv %s not found", tok_tap + 5);
          return;
        }
      }
      else if (!strncmp(tok_tap, "endpt:", 6))
      {
        ct = get_conversation_by_proto_id(proto_get_id_by_short_name(tok_tap + 6));

        if (!ct || !(tap_func = get_endpoint_packet_func(ct)))
        {
          *err_ret = g_strdup_printf(" endpt %s not found", tok_tap + 6);
          return;
        }
      }
      else
      {
        *err_ret = g_strdup_printf("onv/endpt(?): %s not found", tok_tap);
        return;
      }

      ct_tapname = proto_get_protocol_filter_name(get_conversation_proto_id(ct));

      ct_data = g_new0(struct sharkd_conv_tap_data, 1);
      ct_data->type = tok_tap;
      ct_data->hash.user_data = ct_data;

      /* XXX: make configurable */
      ct_data->resolve_name = TRUE;
      ct_data->resolve_port = TRUE;

      tap_error = register_tap_listener(ct_tapname, &ct_data->hash, tap_filter, 0, NULL, tap_func, sharkd_session_process_tap_conv_cb, NULL);

      tap_data = &ct_data->hash;
      tap_free = sharkd_session_free_tap_conv_cb;
    }
    else if (!strncmp(tok_tap, "nstat:", 6))
    {
      stat_tap_table_ui *stat_tap = stat_tap_by_name(tok_tap + 6);
      stat_data_t *stat_data;

      if (!stat_tap)
      {
        *err_ret = g_strdup_printf("nstat=%s not found", tok_tap + 6);
        return;
      }

      stat_tap->stat_tap_init_cb(stat_tap);

      stat_data = g_new0(stat_data_t, 1);
      stat_data->stat_tap_data = stat_tap;
      stat_data->user_data = NULL;

      tap_error = register_tap_listener(stat_tap->tap_name, stat_data, tap_filter, 0, NULL, stat_tap->packet_func, sharkd_session_process_tap_nstat_cb, NULL);

      tap_data = stat_data;
      tap_free = sharkd_session_free_tap_nstat_cb;
    }
    else if (!strncmp(tok_tap, "rtd:", 4))
    {
      return;
      // register_rtd_t *rtd = get_rtd_table_by_name(tok_tap + 4);
      // rtd_data_t *rtd_data;
      // char *err;

      // if (!rtd)
      // {
      //     *err_ret = g_strdup_printf("rtd=%s not found", tok_tap + 4);
      //     return;
      // }

      // rtd_table_get_filter(rtd, "", &tap_filter, &err);
      // if (err != NULL)
      // {
      //     *err_ret = g_strdup_printf("rtd=%s err=%s", tok_tap + 4, err);
      //     g_free(err);
      //     return;
      // }

      // rtd_data = g_new0(rtd_data_t, 1);
      // rtd_data->user_data = rtd;
      // rtd_table_dissector_init(rtd, &rtd_data->stat_table, NULL, NULL);

      // tap_error = register_tap_listener(get_rtd_tap_listener_name(rtd), rtd_data, tap_filter, 0, NULL, get_rtd_packet_func(rtd), sharkd_session_process_tap_rtd_cb, NULL);

      // tap_data = rtd_data;
      // tap_free = sharkd_session_free_tap_rtd_cb;
    }
    else if (!strncmp(tok_tap, "srt:", 4))
    {
      return;
      // register_srt_t *srt = get_srt_table_by_name(tok_tap + 4);
      // srt_data_t *srt_data;
      // char *err;

      // if (!srt)
      // {
      //     *err_ret = g_strdup_printf("srt=%s not found", tok_tap + 4);
      //     return;
      // }

      // srt_table_get_filter(srt, "", &tap_filter, &err);
      // if (err != NULL)
      // {
      //     *err_ret = g_strdup_printf("srt=%s err=%s", tok_tap + 4, err)
      //     g_free(err);
      //     return;
      // }

      // srt_data = g_new0(srt_data_t, 1);
      // srt_data->srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table *));
      // srt_data->user_data = srt;
      // srt_table_dissector_init(srt, srt_data->srt_array);

      // tap_error = register_tap_listener(get_srt_tap_listener_name(srt), srt_data, tap_filter, 0, NULL, get_srt_packet_func(srt), sharkd_session_process_tap_srt_cb, NULL);

      // tap_data = srt_data;
      // tap_free = sharkd_session_free_tap_srt_cb;
    }
    else if (!strncmp(tok_tap, "eo:", 3))
    {
      register_eo_t *eo = get_eo_by_name(tok_tap + 3);

      if (!eo)
      {
        *err_ret = g_strdup_printf("eo=%s not found", tok_tap + 3);
        return;
      }

      tap_error = wg_session_eo_register_tap_listener(eo, tok_tap, tap_filter, wg_session_process_tap_eo_cb, &tap_data, &tap_free);

      /* tap_data & tap_free assigned by sharkd_session_eo_register_tap_listener */
    }
    else if (!strcmp(tok_tap, "rtp-streams"))
    {
      return;
      // tap_error = register_tap_listener("rtp", &rtp_tapinfo, tap_filter, 0, rtpstream_reset_cb, rtpstream_packet_cb, sharkd_session_process_tap_rtp_cb, NULL);

      // tap_data = &rtp_tapinfo;
      // tap_free = rtpstream_reset_cb;
    }
    else if (!strncmp(tok_tap, "rtp-analyse:", 12))
    {
      // struct sharkd_analyse_rtp *rtp_req;

      // rtp_req = (struct sharkd_analyse_rtp *) g_malloc0(sizeof(*rtp_req));
      // if (!sharkd_rtp_match_init(&rtp_req->id, tok_tap + 12))
      // {
      //     rtpstream_id_free(&rtp_req->id);
      //     g_free(rtp_req);
      //     continue;
      // }

      // rtp_req->tap_name = tok_tap;
      // rtp_req->statinfo.first_packet = TRUE;
      // rtp_req->statinfo.reg_pt = PT_UNDEFINED;

      // tap_error = register_tap_listener("rtp", rtp_req, tap_filter, 0, NULL, sharkd_session_packet_tap_rtp_analyse_cb, sharkd_session_process_tap_rtp_analyse_cb, NULL);

      // tap_data = rtp_req;
      // tap_free = sharkd_session_process_tap_rtp_free_cb;
      return;
    }
    else if (!strcmp(tok_tap, "multicast"))
    {
      // mcaststream_tapinfo_t *mcaststream_tapinfo;
      // mcaststream_tapinfo = (mcaststream_tapinfo_t *) g_malloc0(sizeof(*mcaststream_tapinfo));

      // tap_error = register_tap_listener("udp", mcaststream_tapinfo, tap_filter, 0, NULL, mcaststream_packet, sharkd_session_process_tap_multicast_cb, NULL);
      // tap_data = mcaststream_tapinfo;
      // tap_free = sharkd_session_process_free_tap_multicast_cb;
    }
    else if (!strcmp(tok_tap, "phs"))
    {
      // phs_t *rs;

      // pc_proto_id = proto_registrar_get_id_byname("pkt_comment");

      // rs = new_phs_t(NULL, tap_filter);

      // tap_error = register_tap_listener("frame", rs, tap_filter, TL_REQUIRES_PROTO_TREE, NULL,
      //                                   protohierstat_packet,
      //                                   sharkd_session_process_tap_phs_cb, NULL);

      // tap_data = rs;
      // tap_free = sharkd_session_free_tap_phs_cb;
    }
    else if (!strcmp(tok_tap, "voip-calls"))
    {
      // voip_stat_init_tapinfo();

      // tap_error = register_tap_listener("frame", &tapinfo_, tap_filter, 0, NULL, NULL, sharkd_session_process_tap_voip_calls_cb, NULL);

      // tapinfo_.session = cfile.epan;
      // voip_calls_init_all_taps(&tapinfo_);

      // tap_data = &tapinfo_;
      // tap_free = sharkd_session_free_tap_voip_calls_cb;
      return;
    }
    else if (!strncmp(tok_tap, "voip-convs:", 11))
    {
      // int len;
      // unsigned int min, max;
      // struct sharkd_voip_convs_req *voip_convs_req;
      // const char *conv_arg = tok_tap + 11;

      // // parse tok_tap to get which call we are asking for
      // if (*conv_arg == 0) {
      //     // set all bits of voip_conv_sel (-1 in binary is all 1's)
      //     memset(voip_conv_sel, -1, sizeof(voip_conv_sel));
      // } else {
      //     memset(voip_conv_sel, 0, sizeof(voip_conv_sel));

      //     while (*conv_arg != 0) {
      //         if (*conv_arg == ',') {
      //             conv_arg++;
      //         }
      //         if (sscanf(conv_arg, "%u-%u%n", &min, &max, &len) == 2) {
      //             conv_arg += len;
      //         } else if (sscanf(conv_arg, "%u%n", &min, &len) == 1) {
      //             max = min;
      //             conv_arg += len;
      //         } else {
      //             sharkd_json_error(
      //                     rpcid, -11014, NULL,
      //                     "wg_session_process_tap() voip-convs=%s invalid 'convs' parameter", tok_tap
      //             );
      //             return;
      //         }
      //         if (min > max || min >= VOIP_CONV_MAX || max >= VOIP_CONV_MAX) {
      //             sharkd_json_error(
      //                     rpcid, -11012, NULL,
      //                     "wg_session_process_tap() voip-convs=%s invalid 'convs' number range", tok_tap
      //             );
      //             return;
      //         }
      //         for(; min <= max; min++) {
      //             voip_conv_sel[min / VOIP_CONV_BITS] |= 1 << (min % VOIP_CONV_BITS);
      //         }
      //     }
      // }

      // voip_stat_init_tapinfo();

      // voip_convs_req = (struct sharkd_voip_convs_req *) g_malloc0(sizeof(*voip_convs_req));
      // voip_convs_req->tapinfo = &tapinfo_;
      // voip_convs_req->tap_name = tok_tap;

      // tap_error = register_tap_listener("frame", voip_convs_req, tap_filter, 0, NULL, NULL, sharkd_session_process_tap_voip_convs_cb, NULL);

      // tapinfo_.session = cfile.epan;
      // voip_calls_init_all_taps(&tapinfo_);

      // tap_data = voip_convs_req;
      // tap_free = sharkd_session_free_tap_voip_convs_cb;
      return;
    }
    else if (!strncmp(tok_tap, "hosts:", 6))
    {
      gboolean dump_v4;
      gboolean dump_v6;
      struct sharkd_hosts_req *hosts_req;
      const char *proto_arg;
      gchar **proto_tokens;
      gint proto_count;

      proto_arg = tok_tap + 6;

      if (strlen(proto_arg) == 0)
      {
        dump_v4 = TRUE;
        dump_v6 = TRUE;
      }
      else
      {
        dump_v4 = FALSE;
        dump_v6 = FALSE;

        proto_tokens = g_strsplit(proto_arg, ",", 0);
        proto_count = 0;
        while (proto_tokens[proto_count])
        {
          if (!strcmp("ip", proto_tokens[proto_count]) ||
              !strcmp("ipv4", proto_tokens[proto_count]))
          {
            dump_v4 = TRUE;
          }
          else if (!strcmp("ipv6", proto_tokens[proto_count]))
          {
            dump_v6 = TRUE;
          }
          else
          {
            g_strfreev(proto_tokens);
            *err_ret = g_strdup_printf("hosts=%s invalid 'protos' parameter", tok_tap);
            return;
          }
          proto_count++;
        }
        g_strfreev(proto_tokens);
      }

      hosts_req = (struct sharkd_hosts_req *)g_malloc0(sizeof(*hosts_req));
      hosts_req->dump_v4 = dump_v4;
      hosts_req->dump_v6 = dump_v6;
      hosts_req->tap_name = tok_tap;

      tap_error = register_tap_listener("frame", hosts_req, tap_filter, TL_REQUIRES_PROTO_TREE, NULL, NULL, sharkd_session_process_tap_hosts_cb, NULL);

      tap_data = hosts_req;
      tap_free = sharkd_session_free_tap_hosts_cb;
    }
    else
    {
      *err_ret = g_strdup_printf("%s not recognized", tok_tap);
      return;
    }

    if (tap_error)
    {
      *err_ret = g_strdup_printf("name=%s error=%s", tok_tap, tap_error->str);
      g_string_free(tap_error, TRUE);
      if (tap_free)
        tap_free(tap_data);
      return;
    }

    taps_data[taps_count] = tap_data;
    taps_free[taps_count] = tap_free;
    taps_count++;
  }

  fprintf(stderr, "wg_session_process_tap() count=%d\n", taps_count);
  if (taps_count == 0)
  {
    sharkd_json_result_prologue(rpcid);
    sharkd_json_array_open("taps");
    sharkd_json_array_close();
    sharkd_json_result_epilogue();
    return;
  }

  sharkd_json_result_prologue(rpcid);
  sharkd_json_array_open("taps");
  wg_retap(cfile);
  sharkd_json_array_close();
  sharkd_json_result_epilogue();

  for (i = 0; i < taps_count; i++)
  {
    if (taps_data[i])
      remove_tap_listener(taps_data[i]);

    if (taps_free[i])
      taps_free[i](taps_data[i]);
  }
}
