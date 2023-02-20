mergeInto(LibraryManager.library, {
  on_status: function (type, str_ptr) {
    Module.handleStatus(type, UTF8ToString(str_ptr));
  },
});
