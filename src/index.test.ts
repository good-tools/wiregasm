import * as fs from "fs/promises";

import { PrefType, Wiregasm, WiregasmLib, WiregasmLibOverrides } from ".";

import loadWiregasm from "../built/bin/wiregasm.js";
import pako from "pako";

// overrides need to be copied over to every instance
const buildTestOverrides = (): WiregasmLibOverrides => {
  return {
    locateFile: (path, prefix) => {
      if (path.endsWith(".data")) return "built/bin/" + path;
      return prefix + path;
    },
    // supress all unwanted logs in test-suite
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    printErr: () => { },
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    print: () => { },
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    handleStatus: () => { },
  };
};

describe("Wiregasm Library", () => {
  let lib: WiregasmLib;
  beforeAll(async () => {
    lib = await loadWiregasm(buildTestOverrides());
    lib.init();
  });

  afterAll(() => {
    lib.destroy();
  });

  test("columns vector returned correctly", async () => {
    const cols = lib.getColumns();
    expect(cols.size()).toEqual(7);
  });

  test("uploading files without FS works", async () => {
    const uploadDir = lib.getUploadDirectory();

    const data = await fs.readFile("samples/dhcp.pcap");

    // manually allocate data on the heap
    const num_bytes = data.length * data.BYTES_PER_ELEMENT;
    const data_ptr = lib._malloc(num_bytes);
    const data_on_heap = new Uint8Array(lib.HEAPU8.buffer, data_ptr, num_bytes);
    data_on_heap.set(data);

    const fn = "dhcp.pcap";
    const ret = lib.upload(fn, data_on_heap.byteOffset, data.length);

    expect(ret).toEqual(uploadDir + "/" + fn);
    expect(lib.FS.readdir(uploadDir)).toContain(fn);
  });

  test("DissectSession works", async () => {
    const data = await fs.readFile("samples/dhcp.pcap");
    lib.FS.writeFile("/uploads/test.pcap", data);

    const sess = new lib.DissectSession("/uploads/test.pcap");
    const ret = sess.load();

    expect(ret.code).toEqual(0);
    expect(ret.summary.packet_count).toEqual(4);

    const frames = sess.getFrames("", 0, 0);

    expect(frames.matched).toEqual(4);
    expect(frames.frames.size()).toEqual(4);

    const frame = sess.getFrame(1);

    expect(frame.number).toEqual(1);
    expect(frame.data_sources.size()).toBeGreaterThan(0);

    sess.delete();
  });
});

describe("Wiregasm Library Wrapper", () => {
  const wg = new Wiregasm();

  beforeAll(() => {
    return wg.init(loadWiregasm, buildTestOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("columns array returned correctly", async () => {
    const cols = wg.columns();
    expect(cols).toEqual([
      "No.",
      "Time",
      "Source",
      "Destination",
      "Protocol",
      "Length",
      "Info",
    ]);
  });

  test("bin file processed correctly", async () => {
    const ret = wg.load("test.bin", "1234");
    expect(ret.code).toEqual(0);
    expect(ret.summary.packet_count).toEqual(1);
  });

  test("pcap file processed correctly", async () => {
    const data = await fs.readFile("samples/dhcp.pcap");
    const ret = wg.load("dhcp.pcap", data);
    expect(ret.code).toEqual(0);
    expect(ret.summary.packet_count).toEqual(4);

    const frames = wg.frames("", 0, 0);

    expect(frames.matched).toEqual(4);
    expect(frames.frames.size()).toEqual(4);

    const frame = wg.frame(1);
    expect(frame.number).toEqual(1);
    expect(frame.data_sources.size()).toBeGreaterThan(0);
    expect(frame.follow.size()).toBe(1);
    expect(frame.follow.get(0).get(0)).toBe("UDP");
    expect(frame.follow.get(0).get(1)).toBe("udp.stream eq 0");
  });

  test("filter validation works", async () => {
    expect(wg.test_filter("tcp").ok).toBeTruthy();
    expect(wg.test_filter("txx").ok).toBeFalsy();
  });

  test("follow works", async () => {
    const data = await fs.readFile("samples/dhcp.pcap");
    const ret = wg.load("dhcp.pcap", data);
    expect(ret.code).toEqual(0);

    const frame = wg.frame(1);
    const follow = wg.follow(
      frame.follow.get(0).get(0),
      frame.follow.get(0).get(1)
    );
    expect(typeof follow.shost == "string").toBeTruthy();
    expect(typeof follow.sbytes == "number").toBeTruthy();
    expect(typeof follow.sport == "string").toBeTruthy();
    expect(typeof follow.cport == "string").toBeTruthy();
    expect(typeof follow.chost == "string").toBeTruthy();
    expect(typeof follow.cbytes == "number").toBeTruthy();
    expect(follow.payloads.size()).toBeGreaterThan(0);
  });

  test("tap works", async () => {
    const data = await fs.readFile("samples/dhcp.pcap");
    const ret = wg.load("dhcp.pcap", data);
    expect(ret.code).toEqual(0);
    // const res = wg.tap("eo:http");
    const res = wg.tap("stat:http_req");
    expect(res).toBe(1);
  });


  test("downloadFile works", async () => {
    const data = await fs.readFile("samples/http.cap");
    const ret = wg.load("dhcp.pcap", data);
    expect(ret.code).toEqual(0);
    const res = wg.tap("eo:http");
    expect(res).toBe(1);

    const download = wg.download_file("eo:http_0");
    expect(download).toEqual({
      "data": "PGh0bWw+PGhlYWQ+PHN0eWxlPjwhLS0KLmNoe2N1cnNvcjpwb2ludGVyO2N1cnNvcjpoYW5kfWEuYWQ6bGluayB7IGNvbG9yOiAjMDAwMDAwIH1hLmFkOnZpc2l0ZWQgeyBjb2xvcjogIzAwMDAwMCB9YS5hZDpob3ZlciB7IGNvbG9yOiAjMDAwMDAwIH1hLmFkOmFjdGl2ZSB7IGNvbG9yOiAjMDAwMDAwIH1hLnNlYXJjaDpsaW5rIHsgY29sb3I6ICNmZmZmZmYgfWEuc2VhcmNoOnZpc2l0ZWQgeyBjb2xvcjogI2ZmZmZmZiB9YS5zZWFyY2g6aG92ZXIgeyBjb2xvcjogI2ZmZmZmZiB9YS5zZWFyY2g6YWN0aXZlIHsgY29sb3I6ICNmZmZmZmYgfWEuYXR0cmlidXRpb246bGluayB7IGNvbG9yOiAjZmZmZmZmIH1hLmF0dHJpYnV0aW9uOnZpc2l0ZWQgeyBjb2xvcjogI2ZmZmZmZiB9YS5hdHRyaWJ1dGlvbjpob3ZlciB7IGNvbG9yOiAjZmZmZmZmIH1hLmF0dHJpYnV0aW9uOmFjdGl2ZSB7IGNvbG9yOiAjZmZmZmZmIH0gIC8vLS0+PC9zdHlsZT48c2NyaXB0PjwhLS0KZnVuY3Rpb24gc3ModyxpZCkge3dpbmRvdy5zdGF0dXMgPSB3O3JldHVybiB0cnVlO31mdW5jdGlvbiBjcygpe3dpbmRvdy5zdGF0dXM9Jyc7fWZ1bmN0aW9uIGNhKGEpeyB0b3AubG9jYXRpb24uaHJlZj1kb2N1bWVudC5nZXRFbGVtZW50QnlJZChhKS5ocmVmO31mdW5jdGlvbiBnYShvLGUpIHtpZiAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQpIHthPW8uaWQuc3Vic3RyaW5nKDEpO3AgPSAiIjtyID0gIiI7ZyA9IGUudGFyZ2V0O2lmIChnKSB7dCA9IGcuaWQ7ZiA9IGcucGFyZW50Tm9kZTtpZiAoZikge3AgPSBmLmlkO2ggPSBmLnBhcmVudE5vZGU7aWYgKGgpciA9IGguaWQ7fX0gZWxzZSB7aCA9IGUuc3JjRWxlbWVudDtmID0gaC5wYXJlbnROb2RlO2lmIChmKXAgPSBmLmlkO3QgPSBoLmlkO31pZiAodD09YSB8fCBwPT1hIHx8IHI9PWEpcmV0dXJuIHRydWU7dG9wLmxvY2F0aW9uLmhyZWY9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoYSkuaHJlZn19Ly8tLT48L3NjcmlwdD48L2hlYWQ+PGJvZHkgYmdDb2xvcj0iI2ZmZmZmZiIgbGVmdE1hcmdpbj0iMCIgdG9wTWFyZ2luPSIwIiBtYXJnaW53aWR0aD0iMCIgbWFyZ2luaGVpZ2h0PSIwIj48dGFibGUgd2lkdGg9IjQ2OCIgaGVpZ2h0PSI2MCIgY2VsbHNwYWNpbmc9IjEiIGNlbGxwYWRkaW5nPSIwIiBib3JkZXI9IjAiIGJnY29sb3I9IiM2NjY2MzMiPjx0cj48dGQ+PHRhYmxlIHdpZHRoPSI0NjYiIGhlaWdodD0iNTgiIGNlbGxzcGFjaW5nPSIwIiBjZWxscGFkZGluZz0iMSIgYm9yZGVyPSIwIiBiZ2NvbG9yPSIjZmZmZmZmIj48dHI+PHRkIGNvbHNwYW49IjIiIHdpZHRoPSIiIGhlaWdodD0iIj48dGFibGUgd2lkdGg9IjQ2NCIgaGVpZ2h0PSIiIGNlbGxzcGFjaW5nPSIwIiBjZWxscGFkZGluZz0iMiIgYm9yZGVyPSIwIj48dHI+PHRkICBpZD0idGF3MCIgY2xhc3M9ImNoIiB3aWR0aD0iMjI5IiBoZWlnaHQ9IjQxIiBhbGlnbj0ibGVmdCIgdmFsaWduPSJ0b3AiIG9uRm9jdXM9InNzKCdnbyB0byB3d3cuc2VydmZvcmNlLmNvbS8nLCdhdzAnKSIgb25Nb3VzZU92ZXI9InNzKCdnbyB0byB3d3cuc2VydmZvcmNlLmNvbS8nLCdhdzAnKSIgIG9uTW91c2VPdXQ9ImNzKCkiIG9uQ2xpY2s9ImdhKHRoaXMsZXZlbnQpIj48Zm9udCBzdHlsZT0iZm9udC1zaXplOjExcHg7IGZvbnQtZmFtaWx5OnZlcmRhbmEsYXJpYWwsc2Fucy1zZXJpZjsiPjxhIGNsYXNzPSJhZCIgaWQ9ImF3MCIgdGFyZ2V0PSJfdG9wIiBocmVmPSIvcGFnZWFkL2FkY2xpY2s/c2E9bCZhaT1BSmRrZnFzMG9BRmNrczBvZ0FKZTJRRzhEUUstN0I4N200ellBQTM0dEI0VEFHVGY5QkFBMEdPUUFDRUE1UkFBQTNkM2R1VUdkb1ZtY2xGR2J1TTJidEJBTjJnRGUyQXpYaE5IQUFBJm51bT0xJmFkdXJsPWh0dHA6Ly93d3cuc2VydmZvcmNlLmNvbS8lM0ZyZWZlciUzRGdvb2dsZTEmY2xpZW50PWNhLXB1Yi0yMzA5MTkxOTQ4NjczNjI5IiBvbkZvY3VzPSJzcygnZ28gdG8gd3d3LnNlcnZmb3JjZS5jb20vJywnYXcwJykiIG9uTW91c2VPdmVyPSJyZXR1cm4gc3MoJ2dvIHRvIHd3dy5zZXJ2Zm9yY2UuY29tLycsJ2F3MCcpIiAgb25Nb3VzZU91dD0iY3MoKSI+PGI+U2VydkZvcmNlPC9iPjwvYT48L2ZvbnQ+PGJyPjxmb250IHN0eWxlPSJmb250LXNpemU6MTBweDsgZm9udC1mYW1pbHk6dmVyZGFuYSxhcmlhbCxzYW5zLXNlcmlmOyBjb2xvcjojMzMzMzMzIj5EZWRpY2F0ZWQgU2VydmVycyAtICQ3NS9tbyAmYW1wOyB1cCAxVEIgWGZlciBvbmx5ICQxMDAgPC9mb250PjwvdGQ+PHRkICBpZD0idGF3MSIgY2xhc3M9ImNoIiB3aWR0aD0iMjI5IiBoZWlnaHQ9IjQxIiBhbGlnbj0ibGVmdCIgdmFsaWduPSJ0b3AiIG9uRm9jdXM9InNzKCdnbyB0byBMaW51eC5JVHRvb2xib3guY29tJywnYXcxJykiIG9uTW91c2VPdmVyPSJzcygnZ28gdG8gTGludXguSVR0b29sYm94LmNvbScsJ2F3MScpIiAgb25Nb3VzZU91dD0iY3MoKSIgb25DbGljaz0iZ2EodGhpcyxldmVudCkiPjxmb250IHN0eWxlPSJmb250LXNpemU6MTFweDsgZm9udC1mYW1pbHk6dmVyZGFuYSxhcmlhbCxzYW5zLXNlcmlmOyI+PGEgY2xhc3M9ImFkIiBpZD0iYXcxIiB0YXJnZXQ9Il90b3AiIGhyZWY9Ii9wYWdlYWQvYWRjbGljaz9zYT1sJmFpPUFPS1BicXMwb0FGY2tzMG9nQUplMlFHOEQ1cXV5Rk12Z20zWUFBMzR0QjRqQUdUZjlCQUEwR09RQUNJQTVSQUFBM2QzZHVVR2RvVm1jbEZHYnVNMmJ0QkFOMmdEZTJBelhoTkhBQUEmbnVtPTImYWR1cmw9aHR0cDovL2xpbnV4Lml0dG9vbGJveC5jb20vZ3JvdXBzL2dyb3Vwcy5hc3AlM0Z2JTNEUkVESEFULUwmY2xpZW50PWNhLXB1Yi0yMzA5MTkxOTQ4NjczNjI5IiBvbkZvY3VzPSJzcygnZ28gdG8gTGludXguSVR0b29sYm94LmNvbScsJ2F3MScpIiBvbk1vdXNlT3Zlcj0icmV0dXJuIHNzKCdnbyB0byBMaW51eC5JVHRvb2xib3guY29tJywnYXcxJykiICBvbk1vdXNlT3V0PSJjcygpIj48Yj5SZWQgSGF0IERpc2N1c3Npb248L2I+PC9hPjwvZm9udD48YnI+PGZvbnQgc3R5bGU9ImZvbnQtc2l6ZToxMHB4OyBmb250LWZhbWlseTp2ZXJkYW5hLGFyaWFsLHNhbnMtc2VyaWY7IGNvbG9yOiMzMzMzMzMiPkZyZWUgRS1tYWlsIEJhc2VkIFN1cHBvcnQgUmVkIEhhdCBEaXNjdXNzaW9uIEdyb3VwIDwvZm9udD48L3RkPjwvdHI+PC90YWJsZT48L3RkPjwvdHI+PHRyPjx0ZCBub3dyYXAgd2lkdGg9IjElIiBoZWlnaHQ9IjExIiBiZ2NvbG9yPSIjNjY2NjMzIj48L3RkPjx0ZCBub3dyYXAgd2lkdGg9Ijk5JSIgaGVpZ2h0PSIxMSIgYWxpZ249InJpZ2h0IiBiZ2NvbG9yPSIjNjY2NjMzIj48YSBjbGFzcz0iYXR0cmlidXRpb24iIGhyZWY9Ii9wYWdlYWQvdXNlcmZlZWRiYWNrP3VybD1odHRwOi8vd3d3LmV0aGVyZWFsLmNvbS9kb3dubG9hZC5odG1sJmhsPWVuJmFkVT13d3cuc2VydmZvcmNlLmNvbS8mYWRUPVNlcnZGb3JjZSZhZFU9TGludXguSVR0b29sYm94LmNvbSZhZFQ9UmVkK0hhdCtEaXNjdXNzaW9uJmRvbmU9MSIgdGFyZ2V0PSJfYmxhbmsiPjxmb250IHN0eWxlPSJmb250LXNpemU6MTBweDsgZm9udC1mYW1pbHk6dmVyZGFuYSxhcmlhbCxzYW5zLXNlcmlmOyI+QWRzIGJ5IEdvb2dsZTwvZm9udD48L2E+PC90ZD48L3RyPjwvdGFibGU+PC90ZD48L3RyPjwvdGFibGU+PC9ib2R5PjwvaHRtbD4=",
      "file": "ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2Fdownload.html&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633",
      "mime": "text/html"
    });
  });


  test("filter compilation works", async () => {
    expect(wg.complete_filter("tcp").fields.length).toBeGreaterThan(0);
    expect(wg.complete_filter("tcp").fields.find(
      (f) => f.field === "tcp"
    )).toEqual({
      field: "tcp",
      name: "Transmission Control Protocol",
      type: 1,
    });
    expect(wg.complete_filter("txx").fields.length).toBe(0);
  })
});

const buildCompressedOverrides = async (): Promise<WiregasmLibOverrides> => {
  const wasm = pako.inflate(await fs.readFile("built/bin/wiregasm.wasm.gz"));
  const data = pako.inflate(await fs.readFile("built/bin/wiregasm.data.gz"));

  return {
    wasmBinary: wasm.buffer,

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    getPreloadedPackage(_name: string, _size: number): ArrayBuffer {
      return data.buffer;
    },

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    printErr: () => { },
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    print: () => { },
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    handleStatus: () => { },
  };
};

describe("Wiregasm Library - Compressed Loading", () => {
  const wg = new Wiregasm();

  beforeAll(async () => {
    return wg.init(loadWiregasm, await buildCompressedOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("columns array returned correctly", async () => {
    const cols = wg.columns();
    expect(cols).toEqual([
      "No.",
      "Time",
      "Source",
      "Destination",
      "Protocol",
      "Length",
      "Info",
    ]);
  });
});

describe("Wiregasm Library - Module Preferences", () => {
  const wg = new Wiregasm();

  beforeAll(async () => {
    return wg.init(loadWiregasm, await buildCompressedOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("list modules works", async () => {
    const modules = wg.list_modules();
    expect(modules.size()).toBeGreaterThan(0);
  });

  test("list prefs works", async () => {
    const prefs = wg.list_prefs("http");
    expect(prefs.size()).toBeGreaterThan(0);
  });
});

describe("Wiregasm Library - Set Preferences", () => {
  const wg = new Wiregasm();

  beforeAll(async () => {
    return wg.init(loadWiregasm, await buildCompressedOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("setting unknown preference throws error", async () => {
    expect(() => {
      wg.set_pref("http", "unknown", "value");
    }).toThrow();
  });

  test("getting unknown preference throws error", async () => {
    expect(() => {
      wg.get_pref("http", "unknown");
    }).toThrow();
  });

  test("set preferences works", async () => {
    // test defaults
    const pref = wg.get_pref("http", "tcp.port");
    expect(pref.type).toBe(PrefType.PREF_DECODE_AS_RANGE);
    expect(pref.range_value).toBe(
      "80,3128,3132,5985,8080,8088,11371,1900,2869,2710"
    );

    wg.set_pref("http", "tcp.port", "8001");

    const pref2 = wg.get_pref("http", "tcp.port");
    expect(pref2.type).toBe(PrefType.PREF_DECODE_AS_RANGE);
    expect(pref2.range_value).toBe("8001");
  });

  test("set preferences works for diameter", async () => {

    const pref = wg.get_pref("diameter", "tcp.port");
    expect(pref.type).toBe(PrefType.PREF_DECODE_AS_RANGE);
    expect(pref.range_value).toBe(
      "3868"
    );

    wg.set_pref("diameter", "tcp.port", "3871");

    const pref2 = wg.get_pref("diameter", "tcp.port");
    expect(pref2.type).toBe(PrefType.PREF_DECODE_AS_RANGE);
    expect(pref2.range_value).toBe("3871");

    const data = await fs.readFile("samples/diameter_non_standard.pcap");
    const ret = wg.load("diameter_non_standard.pcap", data);

    expect(ret.code).toEqual(0);

    const frame = wg.frame(1);
    const last_tree = frame.tree.get(frame.tree.size() - 1);

    expect(last_tree.label).toBe("Diameter Protocol");
  });

  test("set preferences works for sip", async () => {
    const pref = wg.get_pref("sip", "tcp.port");
    expect(pref.type).toBe(PrefType.PREF_DECODE_AS_RANGE);
    expect(pref.range_value).toBe(
      "5060"
    );

    wg.set_pref("sip", "tcp.port", "8001");

    const pref2 = wg.get_pref("sip", "tcp.port");
    expect(pref2.type).toBe(PrefType.PREF_DECODE_AS_RANGE);
    expect(pref2.range_value).toBe("8001");
  });


});

describe("Wiregasm Library - nghttp2", () => {
  const wg = new Wiregasm();

  beforeAll(async () => {
    return wg.init(loadWiregasm, await buildCompressedOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("enhanced http2 dissection works", async () => {
    const data = await fs.readFile("samples/http2-16-ssl.pcapng");

    // write pre-master secret to file
    // this secret is used to decrypt the TLS traffic
    // it is present in the pcapng file as a comment
    wg.lib.FS.writeFile(
      "/uploads/pre_master_secret",
      Buffer.from(
        "CLIENT_RANDOM 8E83073C735EE9A9D7C471CF9E58E2CDF49FAC8CDE59A4484FC20B8CA17C9E30 A97655616C73DBA996B7A9EACAD4D658D8C2260674798DC843854F57C848D92DAF4F06A9D8BEB45F38C407BD7EB20FD4"
      )
    );

    // set the keylog_file pref
    wg.set_pref("tls", "keylog_file", "/uploads/pre_master_secret");

    const ret = wg.load("http2-16-ssl.pcapng", data);

    expect(ret.code).toEqual(0);

    const frame = wg.frame(14);

    // if http2 decoding works, there should be 3 data sources
    expect(frame.data_sources.size()).toBe(3);

    // the last data source should be the http2 protocol
    const lastDataSource = frame.data_sources.get(2);
    expect(lastDataSource.name).toBe("Decompressed Header (167 bytes)");

    // get the last http2 protocol tree
    const http2ProtoTree = frame.tree.get(frame.tree.size() - 1);
    expect(http2ProtoTree.tree.size()).toBeGreaterThan(0);

    // the first tree should be the http2 headers
    const headersTree = http2ProtoTree.tree.get(0);

    // verify if the label contains the decoded headers
    expect(headersTree.label).toBe(
      "Stream: HEADERS, Stream ID: 1, Length 32, GET /"
    );
  });
});

describe("Wiregasm Library - Lua Dissectors", () => {
  const wg = new Wiregasm();

  beforeAll(async () => {
    return wg.init(
      loadWiregasm,
      await buildCompressedOverrides(),
      async (lib) => {
        const dissector_data = await fs.readFile("samples/dissector.lua");
        lib.FS.writeFile(
          `${lib.getPluginsDirectory()}/dissector.lua`,
          dissector_data
        );
      }
    );
  });

  afterAll(() => {
    wg.destroy();
  });

  test("lua dissector works", async () => {
    const data = await fs.readFile("samples/dns_port.pcap");
    const ret = wg.load("dns_port.pcap", data);

    expect(ret.code).toEqual(0);

    const f = wg.frame(1);
    const myDNSProtoTree = f.tree.get(f.tree.size() - 1);

    expect(myDNSProtoTree.label).toBe("MyDNS Protocol");
  });
});

describe("Wiregasm Library - Reloading Lua Plugins", () => {
  const wg = new Wiregasm();

  beforeAll(async () => {
    return wg.init(loadWiregasm, await buildCompressedOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("reloading lua plugins works", async () => {
    const dissector_data = await fs.readFile("samples/dissector.lua");
    wg.add_plugin("dissector.lua", dissector_data);

    wg.reload_lua_plugins();

    const data = await fs.readFile("samples/dns_port.pcap");
    const ret = wg.load("dns_port.pcap", data);

    expect(ret.code).toEqual(0);

    const f = wg.frame(1);
    const myDNSProtoTree = f.tree.get(f.tree.size() - 1);

    expect(myDNSProtoTree.label).toBe("MyDNS Protocol");
  });
});
