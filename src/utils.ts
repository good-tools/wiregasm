import { Vector } from "./types";

/**
 * Converts a Vector to a JS array
 *
 * @param vec Vector
 * @returns JS array of the Vector contents
 */
export function vectorToArray<T>(vec: Vector<T>): T[] {
  return new Array(vec.size()).fill(0).map((_, id) => vec.get(id));
}
