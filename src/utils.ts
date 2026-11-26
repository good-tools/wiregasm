// SPDX-License-Identifier: GPL-2.0-or-later
import { PrefSetResult, type Vector } from "./types";

/**
 * Converts a Vector to a JS array and frees the Vector
 *
 * @param vec Vector
 * @returns JS array of the Vector contents
 */
export function vectorToArray<T>(vec: Vector<T>): T[] {
  try {
    return Array.from({ length: vec.size() }, (_, i) => vec.get(i));
  } finally {
    // the elements are copied out; free the vector on the wasm heap
    vec.delete();
  }
}

/**
 * Frees an embind object (class instance, vector or map) on the wasm heap.
 */
export function free(handle: unknown): void {
  (handle as { delete(): void }).delete();
}

/**
 * Packs frames into the record format appendFrames() expects: per frame,
 * little-endian, ts_sec u32, ts_usec u32, caplen u16, pad u16, caplen bytes.
 *
 * @param frames Frame payloads, each with an optional Unix timestamp in seconds
 */
export function encodeFrames(
  frames: { ts?: number; data: Uint8Array }[]
): Uint8Array {
  const out = new Uint8Array(
    frames.reduce((n, f) => n + 12 + f.data.length, 0)
  );
  const view = new DataView(out.buffer);

  let off = 0;
  for (const f of frames) {
    const ts = f.ts ?? Date.now() / 1000;
    view.setUint32(off, Math.floor(ts), true);
    view.setUint32(off + 4, Math.floor((ts % 1) * 1e6), true);
    view.setUint16(off + 8, f.data.length, true);
    off += 12;
    out.set(f.data, off);
    off += f.data.length;
  }

  return out;
}

export function preferenceSetCodeToError(code: number): string {
  switch (code) {
    case PrefSetResult.PREFS_SET_SYNTAX_ERR:
      return "Syntax error in string";
    case PrefSetResult.PREFS_SET_NO_SUCH_PREF:
      return "No such preference";
    case PrefSetResult.PREFS_SET_OBSOLETE:
      return "Preference used to exist but no longer does";
    default:
      return "Unknown error";
  }
}
