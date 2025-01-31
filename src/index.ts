import {
  BeforeInitCallback,
  CheckFilterResponse,
  CompleteField,
  DissectSession,
  Download,
  Follow,
  Frame,
  FramesResponse,
  LoadResponse,
  TapInput,
  Pref,
  PrefModule,
  PrefSetResult,
  Vector,
  WiregasmLib,
  WiregasmLibOverrides,
  WiregasmLoader,
  DownloadResponse,
} from "./types";

import { preferenceSetCodeToError, vectorToArray } from "./utils";

/**
 * Wraps the WiregasmLib lib functionality and manages a single DissectSession
 */
export class Wiregasm {
  lib: WiregasmLib;
  initialized: boolean;
  session: DissectSession | null;
  uploadDir: string;
  pluginsDir: string;

  constructor() {
    this.initialized = false;
    this.session = null;
  }

  /**
   * Initialize the wrapper and the Wiregasm module
   *
   * @param loader Loader function for the Emscripten module
   * @param overrides Overrides
   */
  async init(
    loader: WiregasmLoader,
    overrides: WiregasmLibOverrides = {},
    beforeInit: BeforeInitCallback = null
  ) {
    if (this.initialized) {
      return;
    }

    this.lib = await loader(overrides);
    this.uploadDir = this.lib.getUploadDirectory();
    this.pluginsDir = this.lib.getPluginsDirectory();

    if (beforeInit !== null) {
      await beforeInit(this.lib);
    }

    this.lib.init();
    this.initialized = true;
  }

  list_modules(): Vector<PrefModule> {
    return this.lib.listModules();
  }

  list_prefs(module: string): Vector<Pref> {
    return this.lib.listPreferences(module);
  }

  apply_prefs() {
    this.lib.applyPreferences();
  }

  set_pref(module: string, key: string, value: string) {
    const ret = this.lib.setPref(module, key, value);

    if (ret.code != PrefSetResult.PREFS_SET_OK) {
      const message =
        ret.error != "" ? ret.error : preferenceSetCodeToError(ret.code);
      throw new Error(
        `Failed to set preference (${module}.${key}): ${message}`
      );
    }
  }

  get_pref(module: string, key: string): Pref {
    const response = this.lib.getPref(module, key);
    if (response.code != 0) {
      throw new Error(`Failed to get preference (${module}.${key})`);
    }
    return response.data;
  }

  /**
   * Check the validity of a filter expression.
   *
   * @param filter A display filter expression
   */
  test_filter(filter: string): CheckFilterResponse {
    return this.lib.checkFilter(filter);
  }

  complete_filter(filter: string): { fields: CompleteField[] } {
    const out = this.lib.completeFilter(filter);
    return {
      fields: vectorToArray(out.fields),
    };
  }

  tap(taps: TapInput) {
    const out = this.session.tap(JSON.stringify(taps));
    return {
      ...out,
      taps: vectorToArray(out.taps).map((tap) => ({
        ...tap,
        objects: vectorToArray(tap.objects),
      })),
    };;

  }

  download(token: string): DownloadResponse {
    return this.session.download(token);
  }

  reload_lua_plugins() {
    this.lib.reloadLuaPlugins();
  }

  add_plugin(name: string, data: string | ArrayBufferView, opts: object = {}) {
    const path = this.pluginsDir + "/" + name;
    this.lib.FS.writeFile(path, data, opts);
  }

  /**
   * Load a packet trace file for analysis.
   *
   * @returns Response containing the status and summary
   */
  load(
    name: string,
    data: string | ArrayBufferView,
    opts: object = {}
  ): LoadResponse {
    if (this.session != null) {
      this.session.delete();
    }

    const path = this.uploadDir + "/" + name;
    this.lib.FS.writeFile(path, data, opts);

    this.session = new this.lib.DissectSession(path);

    return this.session.load();
  }

  /**
   * Get Packet List information for a range of packets.
   *
   * @param filter Output those frames that pass this filter expression
   * @param skip Skip N frames
   * @param limit Limit the output to N frames
   */
  frames(filter: string, skip = 0, limit = 0): FramesResponse {
    return this.session.getFrames(filter, skip, limit);
  }

  /**
   * Get full information about a frame including the protocol tree.
   *
   * @param number Frame number
   */
  frame(num: number): Frame {
    return this.session.getFrame(num);
  }

  follow(follow: string, filter: string): Follow {
    return this.session.follow(follow, filter);
  }

  destroy() {
    if (this.initialized) {
      if (this.session !== null) {
        this.session.delete();
        this.session = null;
      }

      this.lib.destroy();
      this.initialized = false;
    }
  }

  /**
   * Returns the column headers
   */
  columns(): string[] {
    const vec = this.lib.getColumns();

    // convert it from a vector to array
    return vectorToArray(vec);
  }
}

export * from "./types";
export * from "./utils";
