/* gspawn-wasm.c - Process launching on WebAssembly, no-op implementation
 *
 *  Copyright 2022 Kleis Auke Wolthuizen
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "glib.h"
#include "glibintl.h"
#include "gspawn.h"

G_DEFINE_QUARK (g-exec-error-quark, g_spawn_error)
G_DEFINE_QUARK (g-spawn-exit-error-quark, g_spawn_exit_error)

gboolean
g_spawn_async (const gchar          *working_directory,
               gchar               **argv,
               gchar               **envp,
               GSpawnFlags           flags,
               GSpawnChildSetupFunc  child_setup,
               gpointer              user_data,
               GPid                 *child_pid,
               GError              **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_async is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_async_with_pipes (const gchar          *working_directory,
                          gchar               **argv,
                          gchar               **envp,
                          GSpawnFlags           flags,
                          GSpawnChildSetupFunc  child_setup,
                          gpointer              user_data,
                          GPid                 *child_pid,
                          gint                 *standard_input,
                          gint                 *standard_output,
                          gint                 *standard_error,
                          GError              **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_async_with_pipes is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_async_with_pipes_and_fds (const gchar           *working_directory,
                                  const gchar * const   *argv,
                                  const gchar * const   *envp,
                                  GSpawnFlags            flags,
                                  GSpawnChildSetupFunc   child_setup,
                                  gpointer               user_data,
                                  gint                   stdin_fd,
                                  gint                   stdout_fd,
                                  gint                   stderr_fd,
                                  const gint            *source_fds,
                                  const gint            *target_fds,
                                  gsize                  n_fds,
                                  GPid                  *child_pid_out,
                                  gint                  *stdin_pipe_out,
                                  gint                  *stdout_pipe_out,
                                  gint                  *stderr_pipe_out,
                                  GError               **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_async_with_pipes_and_fds is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_async_with_fds (const gchar          *working_directory,
                        gchar               **argv,
                        gchar               **envp,
                        GSpawnFlags           flags,
                        GSpawnChildSetupFunc  child_setup,
                        gpointer              user_data,
                        GPid                 *child_pid,
                        gint                  stdin_fd,
                        gint                  stdout_fd,
                        gint                  stderr_fd,
                        GError              **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_async_with_fds is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_sync (const gchar          *working_directory,
              gchar               **argv,
              gchar               **envp,
              GSpawnFlags           flags,
              GSpawnChildSetupFunc  child_setup,
              gpointer              user_data,
              gchar               **standard_output,
              gchar               **standard_error,
              gint                 *wait_status,
              GError              **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_sync is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_command_line_sync (const gchar  *command_line,
                           gchar       **standard_output,
                           gchar       **standard_error,
                           gint         *wait_status,
                           GError      **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_command_line_sync is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_command_line_async (const gchar *command_line,
                            GError     **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_command_line_async is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_check_wait_status (gint      wait_status,
			   GError  **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_check_wait_status is no-op on WebAssembly"));
  return FALSE;
}

gboolean
g_spawn_check_exit_status (gint      wait_status,
                           GError  **error)
{
  g_set_error_literal (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED,
                       _("g_spawn_check_exit_status is no-op on WebAssembly"));
  return FALSE;
}

void
g_spawn_close_pid (GPid pid)
{
}
