project('wiregasm', 'cpp')

contrib_path = get_option('prefix')
contrib_lib_dir = join_paths(contrib_path, 'lib')
wireshark_data_path = join_paths(contrib_path, 'share/wireshark')

cxx = meson.get_compiler('cpp')

dependencies = []

# explicitly not using pkg-config, it may add extra link flags (e.g. -pthread)
foreach d : [
    'wireshark',
    'wireshark_common',
    'wsutil',
    'wiretap',
    'glib-2.0',
    'gpg-error',
    'z',
    'pcre2-8',
    'gthread-2.0',
    'gobject-2.0',
    'gmodule-2.0',
    'cares',
    'gcrypt',
    'lua',
    'lrexlib',
    'nghttp2',
  ]
  dependencies += [ cxx.find_library(d, dirs: [ contrib_lib_dir ], required: true) ]
endforeach

include_directories = include_directories(
  join_paths(contrib_path, 'include'),
  join_paths(contrib_path, 'include/glib-2.0'),
  join_paths(contrib_path, 'lib/glib-2.0/include'),
  join_paths(contrib_path, 'include/wireshark'),
)

link_args = [
  '-lembind',

  '-s', 'MODULARIZE=1',
  '-s', 'EXPORT_NAME="loadWiregasm"',
  '-s', 'TOTAL_MEMORY=128MB',

  # XXX: drastically increases binary size, maybe selectively asyncify functions?
  # '-s', 'ASYNCIFY=1',

  # XXX: loaded files can be big
  '-s', 'ALLOW_MEMORY_GROWTH=1',

  # this has a high runtime overhead, can't really do anything
  # about it unless we patch all of the bad function pointer casts
  # in Wireshark and its dependencies
  '-s', 'EMULATE_FUNCTION_POINTER_CASTS=1',

  # runtime deps
  '-s', 'EXPORTED_RUNTIME_METHODS=FS',

  # exported functions
  '-s', 'EXPORTED_FUNCTIONS=_malloc',

  # include our extensions
  '--pre-js', join_paths(meson.source_root(), 'ext/mod.js'),
  '--js-library', join_paths(meson.source_root(), 'ext/lib.js'),

  # put wireshark data at /wireshark
  '--preload-file', wireshark_data_path + '@/wireshark'
]

sources = files([
  'wiregasm.cpp',
  'lib.cpp',
  'bindings.cpp',
  'ssl_key_export.cpp'
])

out = executable(
  'wiregasm',
  sources,
  dependencies : dependencies,
  link_args: link_args,
  include_directories: include_directories,
  install : true
)

# the data file doesn't get recognized currently
# as an output by meson, this is a hack for installing it
custom_target(
  'fake target for installing .data',
  input: out,
  output: ['wiregasm.data'],
  command: [ find_program('true') ],
  install: true,
  install_dir: get_option('bindir')
)

# create gzipped versions of .data and .wasm
gzip = find_program('gzip', required: true)

foreach tgt: [ 'wiregasm.wasm', 'wiregasm.data' ]
  custom_target('gz-' + tgt,
    command: [ gzip, '--keep', '--force', tgt ],
    input: out,
    output: tgt + '.gz',
    install: true,
    install_dir: get_option('bindir'),
  )
endforeach
