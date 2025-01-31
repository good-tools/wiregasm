import { PrefSetResult, Vector } from "./types";

/**
 * Converts a Vector to a JS array
 *
 * @param vec Vector
 * @returns JS array of the Vector contents
 */
export function vectorToArray<T>(vec: Vector<T>): T[] {
  return new Array(vec.size()).fill(0).map((_, id) => vec.get(id));
}

export function isVector(obj: any): obj is Vector<any> {
  // Identify if the object is a vector
  return obj.size !== undefined && obj.get !== undefined;
}

export default function isObject(obj) {
  var type = typeof obj;
  return type === 'function' || (type === 'object' && !!obj);
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
