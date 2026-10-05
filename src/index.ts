// SPDX-License-Identifier: GPL-2.0-or-later
import {
  type BeforeInitCallback,
  type CheckFilterResponse,
  type CompleteField,
  type DissectSession,
  type DownloadResponse,
  type Follow,
  type Frame,
  type FramesResponse,
  type IoGraphResult,
  type HeuristicInfo,
  type LoadResponse,
  type MapInput,
  type Pref,
  type PrefModule,
  PrefSetResult,
  type ProtocolInfo,
  type TapConvResponse,
  type TapExportObjectResponse,
  type TapResponse,
  type Vector,
  type WiregasmLib,
  type WiregasmLibOverrides,
  type WiregasmLoader,
} from "./types";
import { free, preferenceSetCodeToError, vectorToArray } from "./utils";

const ALLOWED_TAP_KEYS = new Set([
  ...Array.from({ length: 15 }, (_, i) => `tap${i}`),
  ...Array.from({ length: 15 }, (_, i) => `filter${i}`),
]);

const ALLOWED_GRAPH_KEYS = new Set([
  "filter",
  "interval",
  ...Array.from({ length: 9 }, (_, i) => `graph${i}`),
  ...Array.from({ length: 9 }, (_, i) => `filter${i}`),
]);

/**
 * Wraps the WiregasmLib lib functionality and manages a single DissectSession
 */
export class Wiregasm {
  // Set by init(); using the wrapper before init() is a programming error.
  lib!: WiregasmLib;
  initialized: boolean;
  session: DissectSession | null;
  uploadDir!: string;
  pluginsDir!: string;

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
    beforeInit: BeforeInitCallback | null = null
  ) {
    if (this.initialized) {
      return;
    }

    this.lib = await loader(overrides);

    if (beforeInit !== null) {
      await beforeInit(this.lib);
    }

    if (!this.lib.init()) {
      throw new Error("Failed to initialize Wiregasm");
    }

    this.uploadDir = this.lib.getUploadDirectory();
    this.pluginsDir = this.lib.getPluginsDirectory();
    this.initialized = true;
  }

  listModules(): Vector<PrefModule> {
    return this.lib.listModules();
  }

  listPrefs(module: string): Vector<Pref> {
    return this.lib.listPreferences(module);
  }

  applyPrefs() {
    this.lib.applyPreferences();
  }

  setPref(module: string, key: string, value: string) {
    const ret = this.lib.setPref(module, key, value);

    if (ret.code !== PrefSetResult.PREFS_SET_OK) {
      const message =
        ret.error !== "" ? ret.error : preferenceSetCodeToError(ret.code);
      throw new Error(
        `Failed to set preference (${module}.${key}): ${message}`
      );
    }
  }

  getPref(module: string, key: string): Pref {
    const response = this.lib.getPref(module, key);
    if (response.code !== 0) {
      throw new Error(`Failed to get preference (${module}.${key})`);
    }
    return response.data;
  }

  /**
   * Check the validity of a filter expression.
   *
   * @param filter A display filter expression
   */
  testFilter(filter: string): CheckFilterResponse {
    return this.lib.checkFilter(filter);
  }

  completeFilter(filter: string): { fields: CompleteField[] } {
    const out = this.lib.completeFilter(filter);
    return {
      fields: vectorToArray(out.fields),
    };
  }

  tap(taps: MapInput) {
    // Validate keys.
    if (!("tap0" in taps)) {
      throw new Error("tap0 is mandatory.");
    }
    if (!Object.keys(taps).every((k) => ALLOWED_TAP_KEYS.has(k))) {
      throw new Error(
        `Invalid arguments. Allowed keys are: ${Array.from(
          ALLOWED_TAP_KEYS
        ).join(", ")}.`
      );
    }

    const session = this.loadedSession();
    const args = new this.lib.MapInput();
    for (const [k, v] of Object.entries(taps)) {
      args.set(k, v);
    }

    let response: ReturnType<DissectSession["tap"]>;
    try {
      response = session.tap(args);
    } finally {
      free(args);
    }
    return {
      error: response.error,
      taps: vectorToArray(response.taps).map((tap) => {
        // biome-ignore lint/suspicious/noExplicitAny: keeps the public return type of tap() unchanged
        let res: any;
        if (this.isConvTap(tap)) {
          res = {
            proto: tap.proto,
            tap: tap.tap,
            type: tap.type,
            geoip: tap.geoip,
            convs: vectorToArray(tap.convs),
            hosts: vectorToArray(tap.hosts),
          };
        } else if (this.isEoTap(tap)) {
          res = {
            proto: tap.proto,
            tap: tap.tap,
            type: tap.type,
            objects: vectorToArray(tap.objects),
          };
        } else {
          free(tap);
          throw new Error("Unknown tap result");
        }
        free(tap);
        return res;
      }),
    };
  }

  download(token: string): DownloadResponse {
    return this.loadedSession().download(token);
  }

  iograph(input: MapInput) {
    // Validate keys.
    if (!("graph0" in input)) {
      throw new Error("graph0 is mandatory.");
    }
    if (!Object.keys(input).every((k) => ALLOWED_GRAPH_KEYS.has(k))) {
      throw new Error(
        `Invalid arguments. Allowed keys are: ${Array.from(
          ALLOWED_GRAPH_KEYS
        ).join(", ")}.`
      );
    }

    const session = this.loadedSession();
    const args = new this.lib.MapInput();
    for (const [k, v] of Object.entries(input)) {
      args.set(k, v);
    }

    let out: IoGraphResult;
    try {
      out = session.iograph(args);
    } finally {
      free(args);
    }
    return {
      ...out,
      iograph: vectorToArray(out.iograph).map((t) => ({
        items: vectorToArray(t.items),
      })),
    };
  }

  reloadLuaPlugins() {
    this.lib.reloadLuaPlugins();
  }

  addPlugin(name: string, data: string | ArrayBufferView, opts: object = {}) {
    const path = `${this.pluginsDir}/${name}`;
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

    const path = `${this.uploadDir}/${name}`;
    this.lib.FS.writeFile(path, data, opts);

    this.session = new this.lib.DissectSession(path);

    const response = this.session.load();
    if (response.code !== 0) {
      // Don't keep a session for a file that failed to open.
      this.session.delete();
      this.session = null;
    }
    return response;
  }

  /**
   * Get Packet List information for a range of packets.
   *
   * @param filter Output those frames that pass this filter expression
   * @param skip Skip N frames
   * @param limit Limit the output to N frames
   */
  frames(filter: string, skip = 0, limit = 0): FramesResponse {
    return this.loadedSession().getFrames(filter, skip, limit);
  }

  /**
   * Get full information about a frame including the protocol tree.
   *
   * @param number Frame number
   */
  frame(num: number): Frame {
    return this.loadedSession().getFrame(num);
  }

  follow(follow: string, filter: string): Follow {
    return this.loadedSession().follow(follow, filter);
  }

  private loadedSession(): DissectSession {
    if (this.session === null) {
      throw new Error("No capture file loaded, call load() first.");
    }
    return this.session;
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

  isEoTap(tap: any): tap is TapExportObjectResponse {
    return tap instanceof this.lib.TapExportObject;
  }

  isConvTap(tap: any): tap is TapConvResponse {
    return tap instanceof this.lib.TapConvResponse;
  }

  // Protocol enable/disable methods

  /**
   * List all registered protocols
   *
   * @returns Array of all protocols with their enabled state
   */
  listProtocols(): ProtocolInfo[] {
    return vectorToArray(this.lib.listProtocols());
  }

  /**
   * Enable or disable a protocol by its ID
   *
   * @param protoId Protocol ID
   * @param enabled Whether to enable or disable the protocol
   * @returns true if successful, false otherwise
   */
  setProtocolEnabled(protoId: number, enabled: boolean): boolean {
    return this.lib.setProtocolEnabled(protoId, enabled);
  }

  /**
   * Enable or disable a protocol by its filter name
   *
   * @param protoName Protocol filter name (e.g., "tcp", "udp")
   * @param enabled Whether to enable or disable the protocol
   * @returns true if successful, false otherwise
   */
  setProtocolEnabledByName(protoName: string, enabled: boolean): boolean {
    return this.lib.setProtocolEnabledByName(protoName, enabled);
  }

  // Heuristic dissector enable/disable methods

  /**
   * List all registered heuristic dissectors
   *
   * @returns Array of all heuristic dissectors with their enabled state
   */
  listHeuristicDissectors(): HeuristicInfo[] {
    return vectorToArray(this.lib.listHeuristicDissectors());
  }

  /**
   * Enable or disable a heuristic dissector by its unique short name
   *
   * @param shortName Unique short name of the heuristic dissector (e.g., "mac_nr_udp")
   * @param enabled Whether to enable or disable the heuristic
   * @returns true if successful, false otherwise
   */
  setHeuristicEnabled(shortName: string, enabled: boolean): boolean {
    return this.lib.setHeuristicEnabled(shortName, enabled);
  }
}

export * from "./types";
export * from "./utils";
