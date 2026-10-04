addToLibrary({
  on_status__deps: ["$UTF8ToString"],
  on_status: function (type, str_ptr) {
    Module.handleStatus(type, UTF8ToString(str_ptr));
  },
});
