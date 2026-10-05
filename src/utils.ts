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
