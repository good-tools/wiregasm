import * as fs from "fs/promises";

import { PrefType, Wiregasm, WiregasmLib, WiregasmLibOverrides } from ".";

import pako from "pako";
import loadWiregasm from "../built/bin/wiregasm.js";

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
  });
});

describe("Wiregasm Library - Export Objects", () => {
  const wg = new Wiregasm();

  beforeAll(() => {
    return wg.init(loadWiregasm, buildTestOverrides());
  });

  afterAll(() => {
    wg.destroy();
  });

  test("tap0 eo:http works", async () => {
    const data = await fs.readFile("samples/http.cap");
    const ret = wg.load("http.cap", data);
    expect(ret.code).toEqual(0);
    const res = wg.tap({ "tap0": "eo:http" });
    expect(res).toStrictEqual({
      "error": "",
      "taps": [
        {
          "objects": [
            {
              "_download": "eo:http_0",
              "filename": (
                "ads?client=ca-pub-2309191948673629&random=1084443430285&" +
                "lmt=1082467020&format=468x60_as&output=html&url=http%3A%2F%2F" +
                "www.ethereal.com%2Fdownload.html&color_bg=FFFFFF&" +
                "color_text=333333&color_link=000000&color_url=666633&" +
                "color_border=666633"
              ),
              "hostname": "pagead2.googlesyndication.com",
              "len": 3608,
              "pkt": 27,
              "type": "text/html",
            },
            {
              "_download": "eo:http_1",
              "filename": "download.html",
              "hostname": "www.ethereal.com",
              "len": 18070,
              "pkt": 38,
              "type": "text/html",
            },
          ],
          "proto": "HTTP",
          "tap": "eo:http",
          "type": "eo",
        },
      ],
    },);
  });

  test("tap0 eo:tftp works", async () => {
    const data = await fs.readFile("samples/tftp_rrq.pcap");
    const ret = wg.load("tftp_rrq.pcap", data);
    expect(ret.code).toEqual(0);
    const res = wg.tap({ "tap0": "eo:tftp" });

    expect(res).toStrictEqual({
      "error": "",
      "taps": [
        {
          "objects": [
            {
              "_download": "eo:tftp_0",
              "filename": "rfc1350.txt",
              "hostname": "",
              "len": 24599,
              "pkt": 98,
              "type": "",
            },
          ],
          "proto": "TFTP",
          "tap": "eo:tftp",
          "type": "eo",
        },
      ],
    },);
  });

  test("download works", async () => {
    const data = await fs.readFile("samples/http.cap");
    const ret = wg.load("dhcp.pcap", data);
    expect(ret.code).toEqual(0);
    const download = wg.download("eo:http_0");
    expect(download.download.data).not.toBe("");
    expect(download.download.mime).toBe("text/html");
    expect(download.download.file).not.toBe("");
    expect(download.error).toBe("");

    const second_file = wg.download("eo:http_1");
    expect(second_file.download.data).not.toBe("");
    expect(second_file.download.mime).toBe("text/html");
    expect(second_file.download.file).toBe("download.html");
    expect(second_file.error).toBe("");
  });

  test("tap0 endpt:Ethernet works", async () => {
    const data = await fs.readFile("samples/http.cap");
    const ret = wg.load("http.cap", data);
    expect(ret.code).toEqual(0);
    const res = wg.tap({ "tap0": "endpt:Ethernet" });
    expect(res).toStrictEqual({
      "error": "",
      "taps": [
        {
          "convs": [],
          "geoip": false,
          "hosts": [
            {
              "filter": "eth.addr==00:00:01:00:00:00",
              "host": "Xerox_00:00:00",
              "port": "",
              "rxb": 22768,
              "rxf": 23,
              "txb": 2323,
              "txf": 20,
            },
            {
              "filter": "eth.addr==fe:ff:20:00:01:00",
              "host": "fe:ff:20:00:01:00",
              "port": "",
              "rxb": 2323,
              "rxf": 20,
              "txb": 22768,
              "txf": 23,
            },
          ],
          "proto": "Ethernet",
          "tap": "endpt:Ethernet",
          "type": "host",
        },
      ],
    },);
  });


  test("tap0 conv:IPv4 works", async () => {
    const data = await fs.readFile("samples/http.cap");
    const ret = wg.load("http.cap", data);
    expect(ret.code).toEqual(0);
    const res = wg.tap({ "tap0": "conv:IPv4" });
    expect(res).toStrictEqual({
      "error": "",
      "taps": [
        {
          "convs": [
            {
              "daddr": "65.208.228.223",
              "dport": "",
              "filter": "ip.addr==145.254.160.237 && ip.addr==65.208.228.223",
              "rxb": 19344,
              "rxf": 18,
              "saddr": "145.254.160.237",
              "sport": "",
              "start": 0,
              "stop": 30.393704,
              "txb": 1351,
              "txf": 16,
            },
            {
              "daddr": "145.253.2.203",
              "dport": "",
              "filter": "ip.addr==145.254.160.237 && ip.addr==145.253.2.203",
              "rxb": 188,
              "rxf": 1,
              "saddr": "145.254.160.237",
              "sport": "",
              "start": 2.553672,
              "stop": 2.91419,
              "txb": 89,
              "txf": 1,
            },
            {
              "daddr": "216.239.59.99",
              "dport": "",
              "filter": "ip.addr==145.254.160.237 && ip.addr==216.239.59.99",
              "rxb": 3236,
              "rxf": 4,
              "saddr": "145.254.160.237",
              "sport": "",
              "start": 2.984291,
              "stop": 4.776868,
              "txb": 883,
              "txf": 3,
            },
          ],
          "geoip": false,
          "hosts": [],
          "proto": "IPv4",
          "tap": "conv:IPv4",
          "type": "conv",
        },
      ],
    },);
  });

  describe("Taps: negative cases", () => {
    test("Unsupported tap values are handled properly", async () => {
      const data = await fs.readFile("samples/http.cap");
      const ret = wg.load("http.cap", data);
      expect(ret.code).toEqual(0);
      const UNSUPPORTED_VALUE = "stat:http";
      const res = wg.tap({ "tap0": UNSUPPORTED_VALUE });
      expect(res).toStrictEqual({
        "error": `${UNSUPPORTED_VALUE} not recognized`,
        "taps": [],
      },);
    });

    ["eo", "conv", "endpt"].map((tap) => {
      test(`Unsupported tap type ${tap} is handled properly`, async () => {
        const data = await fs.readFile("samples/http.cap");
        const ret = wg.load("http.cap", data);
        expect(ret.code).toEqual(0);
        const res = wg.tap({ "tap0": `${tap}:unsupported` });
        expect(res).toStrictEqual({
          "error": `${tap} unsupported not found`,
          "taps": [],
        },);
      });
    });

    test("Missing input values", async () => {
      const data = await fs.readFile("samples/http.cap");
      const ret = wg.load("http.cap", data);
      expect(ret.code).toEqual(0);
      expect(() => {
        wg.tap({})
      }).toThrowError("tap0 is mandatory");
    });
  });
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
