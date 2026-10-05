// SPDX-License-Identifier: GPL-2.0-or-later
#include "lib_internal.h"

using namespace std;

static guint32 cum_bytes;
static frame_data ref_frame;

void cf_close(capture_file *cf) {
  if (cf->state == FILE_CLOSED)
    return; /* Nothing to do */

  if (cf->provider.wth != NULL) {
    wtap_close(cf->provider.wth);
    cf->provider.wth = NULL;
  }
  /* We have no file open... */
  if (cf->filename != NULL) {
    /* If it's a temporary file, remove it. */
    if (cf->is_tempfile) {
      remove(cf->filename);
    }
    g_free(cf->filename);
    cf->filename = NULL;
  }

  /* We have no file open. */
  cf->state = FILE_CLOSED;
}

frame_data *
wg_get_frame(capture_file *cfile, guint32 framenum) {
  return frame_data_sequence_find(cfile->provider.frames, framenum);
}

static const nstime_t *
wg_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num) {
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  if (prov->frames) {
    frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

    return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
wg_epan_new(capture_file *cf) {
  static const struct packet_provider_funcs funcs = {
      wg_get_frame_ts,
      cap_file_provider_get_interface_name,
      cap_file_provider_get_interface_description,
      cap_file_provider_get_modified_block,
      cap_file_provider_get_process_id,
      cap_file_provider_get_process_name,
      cap_file_provider_get_process_uuid};

  return epan_new(&cf->provider, &funcs);
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err) {
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
wg_cf_open(capture_file *cfile, const char *fname, unsigned int type, gboolean is_tempfile, int *err) {
  return cf_open(cfile, fname, type, is_tempfile, err);
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, wtap_rec *rec) {
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
  if (edt) {
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

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &cf->provider.ref, cf->provider.prev_dis);
    if (cf->provider.ref == &fdlocal) {
      ref_frame = fdlocal;
      cf->provider.ref = &ref_frame;
    }

    epan_dissect_run(edt, cf->cd_t, rec,
                     &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cf->provider.prev_cap = cf->provider.prev_dis = frame_data_sequence_add(cf->provider.frames, &fdlocal);

    cf->f_datalen = offset + fdlocal.cap_len;
    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode) {
      if (dfilter_apply_edt(cf->dfcode, edt)) {
        g_hash_table_foreach(edt->pi.fd->dependent_frames, find_and_mark_frame_depended_upon, cf->provider.frames);
      }
    }

    cf->count++;
  } else {
    /* if we don't add it to the frame_data_sequence, clean it up right now
     * to avoid leaks */
    frame_data_destroy(&fdlocal);
  }

  if (edt)
    epan_dissect_reset(edt);

  return passed;
}

static int
load_cap_file(capture_file *cf, int max_packet_count, gint64 max_byte_count, summary_tally *summary) {
  int err;
  gchar *err_info = NULL;
  gint64 data_offset;
  wtap_rec rec;
  epan_dissect_t *edt = NULL;

  // cumulative byte counts start again for each capture file
  cum_bytes = 0;

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

    wtap_rec_init(&rec, 1514);

    while (wtap_read(cf->provider.wth, &rec, &err, &err_info, &data_offset)) {
      if (process_packet(cf, edt, data_offset, &rec)) {
        wtap_rec_reset(&rec);
        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ((--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
          err = 0; /* This is not an error */
          break;
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    wtap_rec_cleanup(&rec);

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

  if (err_info) {
    // XXX: propagate?
    g_free(err_info);
  }

  return err;
}

int wg_load_cap_file(capture_file *cfile, summary_tally *summary) {
  return load_cap_file(cfile, 0, 0, summary);
}

int wg_retap(capture_file *cfile) {
  guint32 framenum;
  frame_data *fdata;
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

  wtap_rec_init(&rec, 1514);
  epan_dissect_init(&edt, cfile->epan, create_proto_tree, false);

  reset_tap_listeners();

  for (framenum = 1; framenum <= cfile->count; framenum++) {
    fdata = wg_get_frame(cfile, framenum);

    if (!wtap_seek_read(cfile->provider.wth, fdata->file_off, &rec, &err, &err_info))
      break;

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = framenum - 1;
    epan_dissect_run_with_taps(&edt, cfile->cd_t, &rec,
                               fdata, cinfo);
    wtap_rec_reset(&rec);
    epan_dissect_reset(&edt);
  }

  wtap_rec_cleanup(&rec);
  epan_dissect_cleanup(&edt);
  draw_tap_listeners(true);

  return 0;
}

int wg_session_process_load(capture_file *cfile, const char *path, summary_tally *summary, char **err_ret) {
  int ret = 0;

  if (!path)
    return 1;

  if (wg_cf_open(cfile, path, WTAP_TYPE_AUTO, FALSE, &ret) != CF_OK) {
    *err_ret = g_strdup_printf("Unable to open the file");
    return 1;
  }

  TRY {
    ret = wg_load_cap_file(cfile, summary);
  }
  CATCH(OutOfMemoryError) {
    *err_ret = g_strdup_printf("Load failed, out of memory");
    ret = ENOMEM;
  }
  ENDTRY;

  return ret;
}
