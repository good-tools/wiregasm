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

