import {
  BeforeInitCallback,
  CheckFilterResponse,
  CompleteField,
  DissectSession,
  DownloadResponse,
  Follow,
  Frame,
  FramesResponse,
  LoadResponse,
  Pref,
  PrefModule,
  PrefSetResult,
  TapConvResponse,
  TapExportObjectResponse,
  TapInput,
  TapResponse,
  Vector,
  WiregasmLib,
  WiregasmLibOverrides,
  WiregasmLoader
} from "./types";

import { preferenceSetCodeToError, vectorToArray } from "./utils";


const ALLOWED_TAP_KEYS = new Set(Array.from({ length: 15 }, (_, i) => `tap${i}`));

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
    // Validate keys.
    if (!("tap0" in taps)) {
      throw new Error("tap0 is mandatory.")
    }
    if (!Object.keys(taps).every((k) => ALLOWED_TAP_KEYS.has(k))) {
      throw new Error(`Invalid arguments. Only tap0..tap15 keys are allowed.`);
    }

    const args = new this.lib.TapInput();
    Object.entries(taps).forEach(([k, v]) => args.set(k, v));

    const response = this.session.tap(args);
    return {
      error: response.error,
      taps: vectorToArray(response.taps).map((tap) => {
        let res;
        if (this.is_cov_tap(tap)) {
          res = {
            proto: tap.proto,
            tap: tap.tap,
            type: tap.type,
            geoip: tap.geoip,
            convs: vectorToArray(tap.convs),
            hosts: vectorToArray(tap.hosts),
          };
        } else if (this.is_eo_tap(tap)) {
          res = {
            proto: tap.proto,
            tap: tap.tap,
            type: tap.type,
            objects: vectorToArray(tap.objects),
          }
        } else {
          (tap as { delete: () => void }).delete();
          throw new Error("Unknown tap result");
        }
        (tap as TapResponse & { delete: () => void }).delete();
        return res;
      }),
    };
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


  is_eo_tap(tap: any): tap is TapExportObjectResponse {
    return tap instanceof this.lib.TapExportObject;
  }

  is_cov_tap(tap: any): tap is TapConvResponse {
    return tap instanceof this.lib.TapConvResponse;
  }
}

export * from "./types";
export * from "./utils";
