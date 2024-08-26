// load the Wiregasm library and pako
//
// pako is only used to inflate the compressed wasm and data files
// if you are not compressing the wasm and data files, you do not need to include pako
//
importScripts(
  "https://cdn.jsdelivr.net/npm/@goodtools/wiregasm/dist/wiregasm.js",
  "https://cdn.jsdelivr.net/npm/pako/dist/pako.js"
);

let lib = null;
let uploadDir = null;
let currentSession = null;

const inflateRemoteBuffer = async (url) => {
  const res = await fetch(url);
  const buf = await res.arrayBuffer();
  return pako.inflate(buf);
};

const fetchPackages = async () => {
  console.log("Fetching packages");
  let [wasm, data] = await Promise.all([
    await inflateRemoteBuffer(
      "https://cdn.jsdelivr.net/npm/@goodtools/wiregasm/dist/wiregasm.wasm.gz"
    ),
    await inflateRemoteBuffer(
      "https://cdn.jsdelivr.net/npm/@goodtools/wiregasm/dist/wiregasm.data.gz"
    ),
  ]);

  return { wasm, data };
};

fetchPackages()
  .then(({ wasm, data }) => {
    loadWiregasm({
      wasmBinary: wasm.buffer,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      getPreloadedPackage(name, size) {
        return data.buffer;
      },
      handleStatus: (type, status) =>
        postMessage({ type: "status", code: type, status: status }),
      handleError: (error) => postMessage({ type: "error", error: error }),
    })
      .then((l) => {
        lib = l;

        if (!lib.init()) {
          throw new Error("Failed to initialize Wiregasm");
        }

        uploadDir = lib.getUploadDirectory();

        postMessage({ type: "init" });
      })
      .catch((e) => {
        postMessage({ type: "error", error: e });
      });
  })
  .catch((e) => {
    postMessage({ type: "error", error: e });
  });

// Event listener to receive messages from the main script
onmessage = function (event) {
  if (!lib) {
    return;
  }

  const data = event.data;

  if (data.type === "process") {
    const f = data.file;
    const reader = new FileReader();
    reader.addEventListener("load", (event) => {
      console.log("Processing", f.name);

      // write the file to the emscripten filesystem
      const buffer = new Uint8Array(event.target.result);
      const path = `${uploadDir}/${f.name}`;
      lib.FS.writeFile(path, buffer);

      // delete the current session if it exists
      if (currentSession !== null) {
        currentSession.delete();
        currentSession = null;
      }

      // create a new session
      currentSession = new lib.DissectSession(path);

      const res = currentSession.load();

      postMessage({ type: "processed", name: f.name, data: res });
    });
    reader.readAsArrayBuffer(f);
  }
};
