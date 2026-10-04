/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */

/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright (C) 2023 Kleis Auke Wolthuizen
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <string.h>
#include "gcontenttype.h"
#include "glibintl.h"

/*< private >*/
void
g_content_type_set_mime_dirs (const gchar * const *dirs)
{
  /* noop on WebAssembly */
}

/*< private >*/
const gchar * const *
g_content_type_get_mime_dirs (void)
{
  const gchar * const *mime_dirs = { NULL };
  return mime_dirs;
}

gboolean
g_content_type_equals (const gchar *type1,
                       const gchar *type2)
{
  g_return_val_if_fail (type1 != NULL, FALSE);
  g_return_val_if_fail (type2 != NULL, FALSE);

  if (g_ascii_strcasecmp (type1, type2) == 0)
    return TRUE;

  return FALSE;
}

gboolean
g_content_type_is_a (const gchar *type,
                     const gchar *supertype)
{
  g_return_val_if_fail (type != NULL, FALSE);
  g_return_val_if_fail (supertype != NULL, FALSE);

  if (g_content_type_equals (type, supertype))
    return TRUE;

  return FALSE;
}

gboolean
g_content_type_is_mime_type (const gchar *type,
                             const gchar *mime_type)
{
  gchar *content_type;
  gboolean ret;

  g_return_val_if_fail (type != NULL, FALSE);
  g_return_val_if_fail (mime_type != NULL, FALSE);

  content_type = g_content_type_from_mime_type (mime_type);
  ret = g_content_type_is_a (type, content_type);
  g_free (content_type);

  return ret;
}

gboolean
g_content_type_is_unknown (const gchar *type)
{
  g_return_val_if_fail (type != NULL, FALSE);

  return strcmp ("*", type) == 0;
}

gchar *
g_content_type_get_description (const gchar *type)
{
  return g_strdup (_("Unknown type"));
}

gchar *
g_content_type_get_mime_type (const gchar *type)
{
  return g_strdup ("application/octet-stream");
}

GIcon *
g_content_type_get_icon (const gchar *type)
{
  return NULL;
}

GIcon *
g_content_type_get_symbolic_icon (const gchar *type)
{
  return NULL;
}

gchar *
g_content_type_get_generic_icon_name (const gchar *type)
{
  return NULL;
}

gboolean
g_content_type_can_be_executable (const gchar *type)
{
  g_return_val_if_fail (type != NULL, FALSE);

  return strcmp (type, ".wasm") == 0;
}

static gboolean
looks_like_text (const guchar *data, 
                 gsize         data_size)
{
  gsize i;
  guchar c;
  for (i = 0; i < data_size; i++)
    {
      c = data[i];
      if (g_ascii_iscntrl (c) && !g_ascii_isspace (c) && c != '\b')
        return FALSE;
    }
  return TRUE;
}

gchar *
g_content_type_from_mime_type (const gchar *mime_type)
{
  return g_strdup ("*");
}

gchar *
g_content_type_guess (const gchar  *filename,
                      const guchar *data,
                      gsize         data_size,
                      gboolean     *result_uncertain)
{
  char *basename;
  char *type;
  char *dot;
  size_t i;

  type = NULL;

  if (result_uncertain)
    *result_uncertain = FALSE;

  /* our test suite and potentially other code used -1 in the past, which is
   * not documented and not allowed; guard against that */
  g_return_val_if_fail (data_size != (gsize) -1, g_strdup ("*"));

  if (filename)
    {
      i = strlen (filename);
      if (i > 0 && filename[i - 1] == G_DIR_SEPARATOR)
        {
          type = g_strdup ("inode/directory");
          if (result_uncertain)
            *result_uncertain = TRUE;
        }
      else
        {
          basename = g_path_get_basename (filename);
          dot = strrchr (basename, '.');
          if (dot)
            type = g_strdup (dot);
          g_free (basename);
        }
    }

  if (type)
    return type;

  if (data && looks_like_text (data, data_size))
    return g_strdup (".txt");

  return g_strdup ("*");
}

GList *
g_content_types_get_registered (void)
{
	return NULL;
}

gchar **
g_content_type_guess_for_tree (GFile *root)
{
  return NULL;
}
