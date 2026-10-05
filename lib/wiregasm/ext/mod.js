// SPDX-License-Identifier: GPL-2.0-or-later
// defaults

if (!Module["print"])
  Module.print = function (text) {
    console.log(text);
  };

if (!Module["printErr"])
  Module.printErr = function (text) {
    console.warn(text);
  };

if (!Module["handleStatus"])
  Module.handleStatus = function (type, status) {
    console.log(type, status);
  };

// initialize FS with directories
Module["onRuntimeInitialized"] = () => {
  Module.FS.mkdir("/plugins");
  Module.FS.mkdir("/uploads");
};
