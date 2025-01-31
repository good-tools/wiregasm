export interface EmscriptenFileSystem {
  writeFile(
    path: string,
    data: string | ArrayBufferView,
    opts?: { flags?: string | undefined }
  ): void;
  readdir(path: string): string[];
  mkdirTree(path: string, mode?: number);
  mkdir(path: string, mode?: number);
}

export interface EmscriptenHeap {
  buffer: ArrayBufferLike;
}

export interface EmscriptenModule {
  FS: EmscriptenFileSystem;
  HEAPU8: EmscriptenHeap;
  _malloc(size: number): number;
}

export interface Vector<T> {
  size(): number;
  get(index: number): T;
}

export interface DataSource {
  name: string;
  data: string;
}

export enum PrefSetResult {
  PREFS_SET_OK, // succeeded
  PREFS_SET_SYNTAX_ERR, // syntax error in string
  PREFS_SET_NO_SUCH_PREF, // no such preference
  PREFS_SET_OBSOLETE, // preference used to exist but no longer does
}

export enum PrefType {
  PREF_UINT = 1 << 0,
  PREF_BOOL = 1 << 1,
  PREF_ENUM = 1 << 2,
  PREF_STRING = 1 << 3,
  PREF_RANGE = 1 << 4,
  PREF_STATIC_TEXT = 1 << 5,
  PREF_UAT = 1 << 6,
  PREF_SAVE_FILENAME = 1 << 7,
  PREF_COLOR = 1 << 8, // These are only supported for "internal" (non-protocol)
  PREF_CUSTOM = 1 << 9, // use and not as a generic protocol preference
  PREF_OBSOLETE = 1 << 10,
  PREF_DIRNAME = 1 << 11,
  PREF_DECODE_AS_UINT = 1 << 12, // These are only supported for "internal" (non-protocol)
  PREF_DECODE_AS_RANGE = 1 << 13, // use and not as a generic protocol preference
  PREF_OPEN_FILENAME = 1 << 14,
  PREF_PASSWORD = 1 << 15, // like string, but never saved to prefs file
}

export interface PrefModule {
  name: string;
  title: string;
  description: string;
  use_gui: boolean;
  submodules: Vector<PrefModule>;
}

export interface PrefSetResponse {
  code: PrefSetResult;
  error: string;
}

export interface PrefResponse {
  code: number;
  data: Pref;
}

export interface Pref {
  name: string;
  title: string;
  description: string;

  type: PrefType;
  uint_value: number;
  uint_base_value: number;
  bool_value: boolean;
  string_value: string;
  range_value: string;
}

export interface ProtoTree {
  label: string;
  filter: string;
  start: number;
  length: number;
  data_source_idx: number;
  type: "proto" | "url" | "framenum" | "";
  url?: string;
  fnum?: number;
  tree: Vector<ProtoTree>;
}

export interface Frame {
  number: number;
  comments: Vector<string>;
  data_sources: Vector<DataSource>;
  tree: Vector<ProtoTree>;
  follow: Vector<Vector<string>>
}

export interface CompleteField {
  field: string;
  type: string;
  name: string;
}


export interface FramesResponse {
  frames: Vector<FrameMeta>;
  matched: number;
}

export interface FollowPayload {
  number: number;
  server: number;
  data: string;
}

export interface Follow {
  shost: string;
  sport: string;
  sbytes: number;
  chost: string;
  cport: string;
  cbytes: number;
  payloads: Vector<FollowPayload>;
}

export interface FrameMeta {
  number: number;
  comments: boolean;
  ignored: boolean;
  marked: boolean;
  bg: number;
  fg: number;
  columns: Vector<string>;
}

export interface LoadSummary {
  filename: string;
  file_type: string;
  file_length: number;
  file_encap_type: string;
  packet_count: number;
  start_time: number;
  stop_time: number;
  elapsed_time: number;
}

export interface LoadResponse {
  code: number;
  error: string;
  summary: LoadSummary;
}

export interface Download {
  file: string;
  mime: string;
  data: string;
}


export interface DownloadResponse {
  error: string;
  download: Download;
}


export type TapInput = Record<string, string>;

interface ExportObject {
  hostname: string;
  pkt: number;
  type: string;
  filename: string;
  _download: string;
  len: number;
}
export interface TapResponse {
  type: string;
  tap: string;
  proto: string;
  objects: Vector<ExportObject>;
}

export interface DissectSession {
  /**
   * Free up any memory used by the session
   */
  delete(): void;

  /**
   * Load a packet trace file for analysis.
   *
   * @returns Response containing the status and summary
   */
  load(): LoadResponse;

  /**
   * Get Packet List information for a range of packets.
   *
   * @param filter Output those frames that pass this filter expression
   * @param skip Skip N frames
   * @param limit Limit the output to N frames
   */
  getFrames(filter: string, skip: number, limit: number): FramesResponse;

  /**
   * Get full information about a frame including the protocol tree.
   *
   * @param number Frame number
   */
  getFrame(number: number): Frame;

  follow(follow: string, filter: string): Follow;

  tap(taps: string): {
    taps: Vector<TapResponse>;
    error: string;
  };

  download(token: string): DownloadResponse;
}

export interface DissectSessionConstructable {
  new(path: string): DissectSession;
}

export interface CheckFilterResponse {
  ok: boolean;
  error: string;
}

export interface WiregasmLibOverrides {
  /**
   * If set, this method will be called when the runtime needs to load a file,
   * such as a .wasm WebAssembly file, .mem memory init file, or a file generated
   * by the file packager. The function receives the relative path to the file as
   * configured in build process and a prefix (path to the main JavaScript file’s
   * directory), and should return the actual URL.
   *
   * This lets you host file packages or the .mem file etc. on a different location
   * than the directory of the JavaScript file (which is the default expectation),
   * for example if you want to host them on a CDN.
   *
   * @param path Path of the requested file.
   * @param prefix Prefix of the requested path. May be empty.
   *
   * @returns Path to the requested file.
   */
  locateFile?(path: string, prefix: string): string;

  /**
   * Called when something is printed to standard error (stderr)
   *
   * @param error Error content
   */
  printErr?(error: string): void;

  /**
   * Called when something is printed to standard output (stdout)
   *
   * @param message Message content
   */
  print?(message: string): void;

  /**
   * Called from within the Wiregasm Library to notify
   * about any status updates.
   *
   * @param type Type of the status
   * @param message Message content
   */
  handleStatus?(type: number, message: string): void;

  /**
   * If you can fetch the binary yourself, you can set it
   */
  wasmBinary?: ArrayBuffer;

  /**
   * If you want to manually manage the download of .data file packages for
   * custom caching, progress reporting and error handling behavior,
   * you can implement this override.
   */
  getPreloadedPackage?(name: string, size: number): ArrayBuffer;
}

export interface WiregasmLib extends EmscriptenModule {
  DissectSession: DissectSessionConstructable;

  /**
   * Returns the directory where files are uploaded
   *
   * @returns Path of the directory
   */
  getUploadDirectory(): string;

  /**
   * Returns the directory where plugins are stored
   *
   * @returns Path of the plugins directory
   */
  getPluginsDirectory(): string;

  /**
   * Initialize the library, load preferences and register dissectors
   */
  init(): boolean;

  /**
   * List all the preference modules

   * @returns List of preference modules
   */
  listModules(): Vector<PrefModule>;

  /**
   * List all the preferences for a given module
   *
   * @param module Preference module
   */
  listPreferences(module: string): Vector<Pref>;

  /**
   * Apply preferences
   */
  applyPreferences(): void;

  /**
   * Set a preference
   *
   * @param module Preference module
   * @param key Preference key
   * @param value Preference value
   */
  setPref(module: string, key: string, value: string): PrefSetResponse;

  /**
   * Get a preference
   *
   * @param module Preference module
   * @param key Preference key
   */
  getPref(module: string, key: string): PrefResponse;

  /**
   * Reload lua plugins
   */
  reloadLuaPlugins(): boolean;

  /**
   * Clean up any memory associated with the lib
   */
  destroy(): void;

  /**
   * Check the validity of a filter expression.
   *
   * @param filter A display filter expression
   */
  checkFilter(filter: string): CheckFilterResponse;

  completeFilter(filter: string): { fields: Vector<CompleteField> };

  download(token: string): Download;
  /**
   * Returns the column headers
   */
  getColumns(): Vector<string>;

  /**
   * Creates a new file in the upload directory with the supplied data
   *
   * @param file_name Name of the file
   * @param data_ptr Pointer to the data
   * @param length Length of the data
   */
  upload(file_name: string, data_ptr: number, length: number): string;
}

export type WiregasmLoader = (
  overrides: WiregasmLibOverrides
) => Promise<WiregasmLib>;

export type BeforeInitCallback = (lib: WiregasmLib) => Promise<void>;
