// Loads the packed package in Chromium from a plain HTML page (e2e/index.html)
// and checks a capture is dissected end to end.
import { expect, test } from "@playwright/test";

test("dissects a capture with the packed package in a browser", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));

  await page.goto("/");
  await page.waitForFunction(() => window.result !== undefined, null, {
    timeout: 90_000,
  });
  const result = await page.evaluate(() => window.result);

  expect(result.error).toBeUndefined();
  expect(errors).toEqual([]);
  expect(result.code).toBe(0);
  expect(result.packets).toBe(43);
  expect(result.firstRow[0]).toBe("1");
  expect(result.layers.slice(0, 4)).toEqual(["frame", "eth", "ip", "tcp"]);
  expect(result.layers).toContain("http");
  expect(result.httpFrames).toBeGreaterThan(0);
});
