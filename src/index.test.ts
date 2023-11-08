import { Wiregasm, WiregasmLib, WiregasmLibOverrides } from ".";
import loadWiregasm from "../built/bin/wiregasm.js";
import * as fs from "fs/promises";
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
    printErr: () => {},
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    print: () => {},
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    handleStatus: () => {},
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
  });

  test("filter validation works", async () => {
    expect(wg.test_filter("tcp").ok).toBeTruthy();
    expect(wg.test_filter("txx").ok).toBeFalsy();
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
    printErr: () => {},
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    print: () => {},
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    handleStatus: () => {},
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
