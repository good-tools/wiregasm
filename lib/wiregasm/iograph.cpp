// SPDX-License-Identifier: GPL-2.0-or-later
#include "lib_internal.h"

#include <climits>

using namespace std;

#define WG_IOGRAPH_MAX_ITEMS 250000 /* 250k limit of items is taken from wireshark-qt, on x86_64 sizeof(io_graph_item_t) is 152, so single graph can take max 36 MB */

struct wg_iograph {
  /* config */
  int hf_index;
  io_graph_item_unit_t calc_type;
  guint32 interval;

  /* result */
  int space_items;
  int num_items;
  io_graph_item_t *items;
  GString *error;
};

static tap_packet_status
wg_iograph_packet(void *g, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_) {
  struct wg_iograph *graph = (struct wg_iograph *)g;
  int idx;
  bool update_succeeded;

  idx = get_io_graph_index(pinfo, graph->interval);
  if (idx < 0 || idx >= WG_IOGRAPH_MAX_ITEMS)
    return TAP_PACKET_DONT_REDRAW;

  if (idx + 1 > graph->num_items) {
    if (idx + 1 > graph->space_items) {
      int new_size = idx + 1024;

      graph->items = (io_graph_item_t *)g_realloc(graph->items, sizeof(io_graph_item_t) * new_size);
      reset_io_graph_items(&graph->items[graph->space_items], new_size - graph->space_items, graph->hf_index);

      graph->space_items = new_size;
    } else if (graph->items == NULL) {
      graph->items = g_new(io_graph_item_t, graph->space_items);
      reset_io_graph_items(graph->items, graph->space_items, graph->hf_index);
    }

    graph->num_items = idx + 1;
  }

  update_succeeded = update_io_graph_item(graph->items, idx, pinfo, edt, graph->hf_index, graph->calc_type, graph->interval);
  /* XXX - TAP_PACKET_FAILED if the item couldn't be updated, with an error message? */
  return update_succeeded ? TAP_PACKET_REDRAW : TAP_PACKET_DONT_REDRAW;
}

/**
 * wg_session_process_iograph()
 *
 * Process iograph request
 *
 * Input:
 *   (o) interval - interval time in ms, if not specified: 1000ms
 *   (m) graph0             - First graph request
 *   (o) graph1...graph9    - Other graph requests
 *   (o) filter0            - First graph filter
 *   (o) filter1...filter9  - Other graph filters
 *
 * Graph requests can be one of: "packets", "bytes", "bits", "sum:<field>", "frames:<field>", "max:<field>", "min:<field>", "avg:<field>", "load:<field>",
 * if you use variant with <field>, you need to pass field name in filter request.
 *
 * Output object with attributes:
 *       error   - graph cannot be constructed
 *   (m) iograph - array of graph results with attributes:
 *                  items  - graph values.
 */
IoGraphResult wg_session_process_iograph(capture_file *cfile, MapInput input) {
  IoGraphResult buf;
  // interval should be an integer
  auto interval_it = input.find("interval");
  const char *tok_interval = interval_it != input.end() ? interval_it->second.c_str() : NULL;
  struct wg_iograph graphs[10];
  bool is_any_ok = false;
  int graph_count;

  guint32 interval_ms = 1000; /* default: one per second */
  int i;

  if (tok_interval)
    ws_strtou32(tok_interval, NULL, &interval_ms);

  if (interval_ms <= 0) {
    buf.error = "The value for interval must be a positive integer";
    return buf;
  }

  /* Wireshark's IO graph APIs take the interval in microseconds, as an int. */
  if (interval_ms > INT_MAX / 1000) {
    buf.error = "The value for interval is too large";
    return buf;
  }

  for (i = graph_count = 0; i < (int)G_N_ELEMENTS(graphs); i++) {
    struct wg_iograph *graph = &graphs[graph_count];

    const char *tok_graph;
    const char *tok_filter;
    char tok_format_buf[32];
    const char *field_name;

    snprintf(tok_format_buf, sizeof(tok_format_buf), "graph%d", i);
    auto graph_it = input.find(tok_format_buf);
    if (graph_it == input.end()) {
      if (i == 0) {
        buf.error = "graph0 is mandatory";
        return buf;
      }
      break;
    }
    tok_graph = graph_it->second.c_str();

    snprintf(tok_format_buf, sizeof(tok_format_buf), "filter%d", i);
    auto filter_it = input.find(tok_format_buf);
    tok_filter = filter_it != input.end() ? filter_it->second.c_str() : NULL;

    if (!strcmp(tok_graph, "packets"))
      graph->calc_type = IOG_ITEM_UNIT_PACKETS;
    else if (!strcmp(tok_graph, "bytes"))
      graph->calc_type = IOG_ITEM_UNIT_BYTES;
    else if (!strcmp(tok_graph, "bits"))
      graph->calc_type = IOG_ITEM_UNIT_BITS;
    else if (g_str_has_prefix(tok_graph, "sum:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_SUM;
    else if (g_str_has_prefix(tok_graph, "frames:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_FRAMES;
    else if (g_str_has_prefix(tok_graph, "fields:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_FIELDS;
    else if (g_str_has_prefix(tok_graph, "max:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_MAX;
    else if (g_str_has_prefix(tok_graph, "min:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_MIN;
    else if (g_str_has_prefix(tok_graph, "avg:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_AVERAGE;
    else if (g_str_has_prefix(tok_graph, "load:"))
      graph->calc_type = IOG_ITEM_UNIT_CALC_LOAD;
    else
      break;

    field_name = strchr(tok_graph, ':');
    if (field_name)
      field_name = field_name + 1;

    /* Convert milliseconds to microseconds for Wireshark internal IO graph APIs. */
    graph->interval = interval_ms * 1000;

    graph->hf_index = -1;
    graph->error = check_field_unit(field_name, &graph->hf_index, graph->calc_type);

    graph->space_items = 0; /* TODO, can avoid realloc()s in wg_iograph_packet() by calculating: capture_time / interval */
    graph->num_items = 0;
    graph->items = NULL;

    if (!graph->error)
      graph->error = register_tap_listener(
          "frame",
          graph,
          tok_filter,
          TL_REQUIRES_PROTO_TREE,
          NULL,
          wg_iograph_packet,
          NULL,
          NULL);

    graph_count++;

    if (graph->error) {
      buf.error = graph->error->str;
      g_string_free(graph->error, true);
      /* The earlier graphs registered tap listeners pointing into `graphs`,
         which is about to go out of scope: remove them. */
      for (int j = 0; j < graph_count - 1; j++) {
        remove_tap_listener(&graphs[j]);
        g_free(graphs[j].items);
      }
      return buf;
    }

    if (graph->error == NULL)
      is_any_ok = true;
  }

  /* retap only if we have at least one ok */
  if (is_any_ok)
    wg_retap(cfile);

  for (i = 0; i < graph_count; i++) {
    struct wg_iograph *graph = &graphs[i];
    IoGraph g;

    if (graph->error) {
      g_string_free(graph->error, true);
      buf.error = g_strdup_printf("Error processing graph %d", i);
      return buf;
    } else {
      int idx;

      for (idx = 0; idx < graph->num_items; idx++) {
        double val;

        val = get_io_graph_item(
            graph->items,
            graph->calc_type,
            idx,
            graph->hf_index,
            cfile,
            graph->interval,
            graph->num_items,
            false /* asAOT: 4.6 option; false keeps the previous behaviour */);

        g.items.push_back(val);
      }
    }
    buf.iograph.push_back(g);
    remove_tap_listener(graph);
    g_free(graph->items);
  }
  return buf;
}
