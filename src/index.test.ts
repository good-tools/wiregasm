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
    const data = await fs.readFile("samples/tftp_rrq.pcap");
    const ret = wg.load("tftp_rrq.pcap", data);
    expect(ret.code).toEqual(0);
    // const res = wg.tap("eo:http");
    // const res = wg.tap("eo");

    const download = wg.download_file("eo:tftp_0");

    // const download = wg.download_file("eo:http_0")
    expect(download).toEqual({ "data": "", "file": "", "mime": "" })

    // expect(res).toBe(1);
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

    const new_download = wg.download_file("eo:http_1");
    expect(new_download).toEqual({
      "data": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIGh0bWwKICBQVUJMSUMgIi0vL1czQy8vRFREIFhIVE1MIDEuMCBTdHJpY3QvL0VOIgogICJEVEQveGh0bWwxLXN0cmljdC5kdGQiPgo8aHRtbCB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCIgeG1sOmxhbmc9ImVuIiBsYW5nPSJlbiI+CiAgPGhlYWQ+CiAgICA8dGl0bGU+RXRoZXJlYWw6IERvd25sb2FkPC90aXRsZT4KICAgIDxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyIgbWVkaWE9ImFsbCI+CglAaW1wb3J0IHVybCgibW0vY3NzL2V0aGVyZWFsLTMtMC5jc3MiKTsKICAgIDwvc3R5bGU+CjwvaGVhZD4KICA8Ym9keT4KICAgIDxkaXYgY2xhc3M9InRvcCI+CiAgICA8dGFibGUgd2lkdGg9IjEwMCUiIGNlbGxzcGFjaW5nPSIwIiBjZWxscGFkZGluZz0iMCIgYm9yZGVyPSIwIiBzdW1tYXJ5PSIiPgogICAgICA8dHI+CiAgICAgICAgPHRkIHZhbGlnbj0ibWlkZGxlIiB3aWR0aD0iMSI+CgkgIDxhIGhyZWY9Ii8iPjxpbWcgY2xhc3M9ImxvZ28iIHRpdGxlPSJFdGhlcmVhbCBob21lIiBzcmM9Im1tL2ltYWdlL2Vsb2dvLTY0LXRyYW5zLmdpZiIgYWx0PSIiIHdpZHRoPSI2NCIgaGVpZ2h0PSI2NCI+PC9pbWc+PC9hPgogICAgICAgIDwvdGQ+CiAgICAgICAgPHRkIGFsaWduPSJsZWZ0IiB2YWxpZ249Im1pZGRsZSI+CiAgICAgICAgICA8aDI+RXRoZXJlYWw8L2gyPgogICAgICAgICAgPGg1IHN0eWxlPSJ3aGl0ZS1zcGFjZTogbm93cmFwOyI+RG93bmxvYWQ8L2g1PgogICAgICAgIDwvdGQ+CiAgICAgICAgPHRkIGFsaWduPSJyaWdodCI+CgkgICAgPHRhYmxlIHN0eWxlPSJtYXJnaW4tcmlnaHQ6IDEwcHg7IiBjZWxsc3BhY2luZz0iMCIgY2VsbHBhZGRpbmc9IjAiIGJvcmRlcj0iMCIgc3VtbWFyeT0iIj4KICAgICAgICAgICAgICA8Zm9ybSBuYW1lPSJzZWFyY2giIG1ldGhvZD0icG9zdCIgYWN0aW9uPSJodHRwOi8vd3d3LmV0aGVyZWFsLmNvbS9jZ2ktYmluL2h0c2VhcmNoIj4KICAgICAgICAgICAgICA8dHI+CgkgICAgICAgIDx0ZD4KCSAgICAgICAgICA8ZGl2IGNsYXNzPSJ0b3Bmb3JtdGV4dCI+CiAgICAgICAgICAgICAgICAgIDxhIGhyZWY9InNlYXJjaC5odG1sIj5TZWFyY2g6PC9hPgoJCSAgPC9kaXY+CgkgICAgICAgIDwvdGQ+CgkgICAgICAgIDx0ZD4KCSAgICAgICAgICA8ZGl2IGNsYXNzPSJ0b3Bmb3JtdGV4dCI+CiAgICAgICAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBzaXplPSIxMiIgbmFtZT0id29yZHMiPgoJCSAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iY29uZmlnIiB2YWx1ZT0iZXRoZXJlYWwiPgoJCSAgPC9kaXY+CgkgICAgICAgIDwvdGQ+CgkJPHRkIHZhbGlnbj0iYm90dG9tIj4KCQkgIDxpbnB1dCB0eXBlPSJpbWFnZSIgY2xhc3M9ImdvYnV0dG9uIiBzcmM9Im1tL2ltYWdlL2dvLWJ1dHRvbi5naWYiPgoJCTwvdGQ+CiAgICAgICAgICAgICAgPC90cj4KICAgICAgICAgICAgICA8L2Zvcm0+CjwvdGFibGU+CgkgIDwvZGl2PgogICAgICAgIDwvdGQ+CiAgICAgIDwvdHI+CiAgICA8L3RhYmxlPgogICAgPC9kaXY+CjxkaXYgY2xhc3M9InNpdGViYXIiPgo8cD4KICA8YSBocmVmPSIvIj5Ib21lPC9hPgogIDxzcGFuIGNsYXNzPSJzaXRlYmFyc2VwIj58PC9zcGFuPgogIDxhIGhyZWY9ImludHJvZHVjdGlvbi5odG1sIj5JbnRyb2R1Y3Rpb248L2E+CiAgPHNwYW4gY2xhc3M9InNpdGViYXJzZXAiPnw8L3NwYW4+CiAgRG93bmxvYWQKICA8c3BhbiBjbGFzcz0ic2l0ZWJhcnNlcCI+fDwvc3Bhbj4KICA8YSBocmVmPSJkb2NzLyI+RG9jdW1lbnRhdGlvbjwvYT4KICA8c3BhbiBjbGFzcz0ic2l0ZWJhcnNlcCI+fDwvc3Bhbj4KICA8YSBocmVmPSJsaXN0cy8iPkxpc3RzPC9hPgogIDxzcGFuIGNsYXNzPSJzaXRlYmFyc2VwIj58PC9zcGFuPgogIDxhIGhyZWY9ImZhcS5odG1sIj5GQVE8L2E+CiAgPHNwYW4gY2xhc3M9InNpdGViYXJzZXAiPnw8L3NwYW4+CiAgPGEgaHJlZj0iZGV2ZWxvcG1lbnQuaHRtbCI+RGV2ZWxvcG1lbnQ8L2E+CjwvcD4KPC9kaXY+CjxkaXYgY2xhc3M9Im5hdmJhciI+CjxwPgogIDxhIGhyZWY9IiNyZWxlYXNlcyI+T2ZmaWNpYWwgUmVsZWFzZXM8L2E+CiAgPHNwYW4gY2xhc3M9Im5hdmJhcnNlcCI+fDwvc3Bhbj4KICA8YSBocmVmPSIjb3RoZXJwbGF0Ij5PdGhlciBQbGF0Zm9ybXM8L2E+CiAgPHNwYW4gY2xhc3M9Im5hdmJhcnNlcCI+fDwvc3Bhbj4KICA8YSBocmVmPSIjb3RoZXJkb3duIj5PdGhlciBEb3dubG9hZHM8L2E+CiAgPHNwYW4gY2xhc3M9Im5hdmJhcnNlcCI+fDwvc3Bhbj4KICA8YSBocmVmPSIjbGVnYWwiPkxlZ2FsIE5vdGljZXM8L2E+CjwvcD4KPC9kaXY+CjwhLS0gQmVnaW4gQWQgNDY4eDYwIC0tPgo8ZGl2IGNsYXNzPSJhZGJsb2NrIj4KPHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiPjwhLS0KZ29vZ2xlX2FkX2NsaWVudCA9ICJwdWItMjMwOTE5MTk0ODY3MzYyOSI7Cmdvb2dsZV9hZF93aWR0aCA9IDQ2ODsKZ29vZ2xlX2FkX2hlaWdodCA9IDYwOwpnb29nbGVfYWRfZm9ybWF0ID0gIjQ2OHg2MF9hcyI7Cmdvb2dsZV9jb2xvcl9ib3JkZXIgPSAiNjY2NjMzIjsKZ29vZ2xlX2NvbG9yX2JnID0gIkZGRkZGRiI7Cmdvb2dsZV9jb2xvcl9saW5rID0gIjAwMDAwMCI7Cmdvb2dsZV9jb2xvcl91cmwgPSAiNjY2NjMzIjsKZ29vZ2xlX2NvbG9yX3RleHQgPSAiMzMzMzMzIjsKLy8tLT48L3NjcmlwdD4KPHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiCiAgc3JjPSJodHRwOi8vcGFnZWFkMi5nb29nbGVzeW5kaWNhdGlvbi5jb20vcGFnZWFkL3Nob3dfYWRzLmpzIj4KPC9zY3JpcHQ+CjwvZGl2Pgo8IS0tIEVuZCBBZCAtLT4KPGRpdiBjbGFzcz0iYmxvY2siPgogIDxoMiBjbGFzcz0iaGVhZGVybGluZSIgaWQ9InJlbGVhc2VzIj5PZmZpY2lhbCBSZWxlYXNlczwvaDI+CjxwPgogIFRoZSBPZmZpY2lhbCBzb3VyY2UgY29kZSByZWxlYXNlIGFuZCBpbnN0YWxsZXJzIGZvciBXaW5kb3dzLCBSZWQgSGF0CiAgTGludXgvRmVkb3JhLCBhbmQgU29sYXJpcyBjYW4gYmUgZm91bmQgb24gdGhlIG1haW4gRXRoZXJlYWwgd2ViIHNpdGUgYW5kCiAgaXRzIG1pcnJvcnMuCjwvcD4KPGg0PlNvdXJjZSBDb2RlPC9oND4KPHA+CkhUVFA6CjxhIGhyZWY9Imh0dHA6Ly93d3cuZXRoZXJlYWwuY29tL2Rpc3RyaWJ1dGlvbi8iPk1haW4gc2l0ZTwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLnBsYW5ldG1pcnJvci5jb20vZGlzdHJpYnV0aW9uLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJodHRwOi8vd3d3Lm1pcnJvcnMud2lyZXRhcHBlZC5uZXQvc2VjdXJpdHkvcGFja2V0LWNhcHR1cmUvZXRoZXJlYWwvIj5BdXN0cmFsaWE8L2E+CjxhIGhyZWY9Imh0dHA6Ly9uZXRtaXJyb3Iub3JnL21pcnJvci9mdHAuZXRoZXJlYWwuY29tLyI+R2VybWFueTwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLm5ldGFyYy5qcC9kaXN0cmlidXRpb24vIj5KYXBhbjwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLnNlY3V3aXouY29tL2Rpc3RyaWJ1dGlvbi8iPktvcmVhPC9hPgo8YSBocmVmPSJodHRwOi8vZXRoZXJlYWwuMG5pMG4ub3JnL2Rpc3RyaWJ1dGlvbi8iPk1hbGF5c2lhPC9hPgo8YSBocmVmPSJodHRwOi8vZnRwLnN1bmV0LnNlL3B1Yi9uZXR3b3JrL21vbml0b3JpbmcvZXRoZXJlYWwvIj5Td2VkZW48L2E+CjxhIGhyZWY9Imh0dHA6Ly9zb3VyY2Vmb3JnZS5uZXQvcHJvamVjdC9zaG93ZmlsZXMucGhwP2dyb3VwX2lkPTI1NSI+U291cmNlRm9yZ2U8L2E+CjwvcD4KPHA+CkZUUDoKPGEgaHJlZj0iZnRwOi8vZnRwLmV0aGVyZWFsLmNvbS9wdWIvZXRoZXJlYWwvIj5NYWluIHNpdGU8L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5wbGFuZXRtaXJyb3IuY29tL3B1Yi9ldGhlcmVhbC8iPkF1c3RyYWxpYTwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLm1pcnJvcnMud2lyZXRhcHBlZC5uZXQvcHViL3NlY3VyaXR5L3BhY2tldC1jYXB0dXJlL2V0aGVyZWFsLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJmdHA6Ly9nZC50dXdpZW4uYWMuYXQvaW5mb3N5cy9zZWN1cml0eS9ldGhlcmVhbC8iPkF1c3RyaWE8L2E+CjxhIGhyZWY9ImZ0cDovL25ldG1pcnJvci5vcmcvZnRwLmV0aGVyZWFsLmNvbS8iPkdlcm1hbnk8L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5heWFtdXJhLm9yZy9wdWIvZXRoZXJlYWwvIj5KYXBhbjwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLmF6Yy51YW0ubXgvbWlycm9ycy9ldGhlcmVhbC8iPk1leGljbzwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLnN1bmV0LnNlL3B1Yi9uZXR3b3JrL21vbml0b3JpbmcvZXRoZXJlYWwvIj5Td2VkZW48L2E+CjwvcD4KPHA+ClRoZSBsYXRlc3QgZGV2ZWxvcG1lbnQgc291cmNlcyBhcmUgYXZhaWxhYmxlIHZpYQo8YSBocmVmPSJkZXZlbG9wbWVudC5odG1sI2Fub25jdnMiPmFub255bW91cyBDVlM8L2E+Lgo8L3A+CjxoND5XaW5kb3dzIDk4L01FLzIwMDAvWFAvMjAwMyBJbnN0YWxsZXJzPC9oND4KPHA+CkhUVFA6CjxhIGhyZWY9Imh0dHA6Ly93d3cuZXRoZXJlYWwuY29tL2Rpc3RyaWJ1dGlvbi93aW4zMi8iPk1haW4gc2l0ZTwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLnBsYW5ldG1pcnJvci5jb20vZGlzdHJpYnV0aW9uL3dpbjMyLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJodHRwOi8vd3d3Lm1pcnJvcnMud2lyZXRhcHBlZC5uZXQvc2VjdXJpdHkvcGFja2V0LWNhcHR1cmUvZXRoZXJlYWwvd2luMzIvIj5BdXN0cmFsaWE8L2E+CjxhIGhyZWY9Imh0dHA6Ly9uZXRtaXJyb3Iub3JnL21pcnJvci9mdHAuZXRoZXJlYWwuY29tL3dpbjMyLyI+R2VybWFueTwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLm5ldGFyYy5qcC9kaXN0cmlidXRpb24vd2luMzIvIj5KYXBhbjwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLnNlY3V3aXouY29tL2Rpc3RyaWJ1dGlvbi93aW4zMi8iPktvcmVhPC9hPgo8YSBocmVmPSJodHRwOi8vZXRoZXJlYWwuMG5pMG4ub3JnL2Rpc3RyaWJ1dGlvbi93aW4zMi8iPk1hbGF5c2lhPC9hPgo8YSBocmVmPSJodHRwOi8vZnRwLnN1bmV0LnNlL3B1Yi9uZXR3b3JrL21vbml0b3JpbmcvZXRoZXJlYWwvd2luMzIvIj5Td2VkZW48L2E+CjxhIGhyZWY9Imh0dHA6Ly9zb3VyY2Vmb3JnZS5uZXQvcHJvamVjdC9zaG93ZmlsZXMucGhwP2dyb3VwX2lkPTI1NSI+U291cmNlRm9yZ2U8L2E+CjwvcD4KPHA+CkZUUDoKPGEgaHJlZj0iZnRwOi8vZnRwLmV0aGVyZWFsLmNvbS9wdWIvZXRoZXJlYWwvd2luMzIvIj5NYWluIHNpdGU8L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5wbGFuZXRtaXJyb3IuY29tL3B1Yi9ldGhlcmVhbC93aW4zMi8iPkF1c3RyYWxpYTwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLm1pcnJvcnMud2lyZXRhcHBlZC5uZXQvcHViL3NlY3VyaXR5L3BhY2tldC1jYXB0dXJlL2V0aGVyZWFsL3dpbjMyLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJmdHA6Ly9nZC50dXdpZW4uYWMuYXQvaW5mb3N5cy9zZWN1cml0eS9ldGhlcmVhbC93aW4zMi8iPkF1c3RyaWE8L2E+CjxhIGhyZWY9ImZ0cDovL25ldG1pcnJvci5vcmcvZnRwLmV0aGVyZWFsLmNvbS93aW4zMi8iPkdlcm1hbnk8L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5heWFtdXJhLm9yZy9wdWIvZXRoZXJlYWwvd2luMzIvIj5KYXBhbjwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLmF6Yy51YW0ubXgvbWlycm9ycy9ldGhlcmVhbC93aW4zMi8iPk1leGljbzwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLnN1bmV0LnNlL3B1Yi9uZXR3b3JrL21vbml0b3JpbmcvZXRoZXJlYWwvd2luMzIvIj5Td2VkZW48L2E+CjwvcD4KPGg0PlJlZCBIYXQgTGludXggLyBGZWRvcmEgUGFja2FnZXM8L2g0Pgo8cD4KSFRUUDoKPGEgaHJlZj0iaHR0cDovL3d3dy5ldGhlcmVhbC5jb20vZGlzdHJpYnV0aW9uL3JwbXMvIj5NYWluIHNpdGU8L2E+CjxhIGhyZWY9Imh0dHA6Ly9ldGhlcmVhbC5wbGFuZXRtaXJyb3IuY29tL2Rpc3RyaWJ1dGlvbi9ycG1zLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJodHRwOi8vd3d3Lm1pcnJvcnMud2lyZXRhcHBlZC5uZXQvc2VjdXJpdHkvcGFja2V0LWNhcHR1cmUvZXRoZXJlYWwvcnBtcy8iPkF1c3RyYWxpYTwvYT4KPGEgaHJlZj0iaHR0cDovL25ldG1pcnJvci5vcmcvbWlycm9yL2Z0cC5ldGhlcmVhbC5jb20vcnBtcy8iPkdlcm1hbnk8L2E+CjxhIGhyZWY9Imh0dHA6Ly9ldGhlcmVhbC5uZXRhcmMuanAvZGlzdHJpYnV0aW9uL3JwbXMvIj5KYXBhbjwvYT4KPGEgaHJlZj0iaHR0cDovL2V0aGVyZWFsLnNlY3V3aXouY29tL2Rpc3RyaWJ1dGlvbi9ycG1zLyI+S29yZWE8L2E+CjxhIGhyZWY9Imh0dHA6Ly9ldGhlcmVhbC4wbmkwbi5vcmcvZGlzdHJpYnV0aW9uL3JwbXMvIj5NYWxheXNpYTwvYT4KPGEgaHJlZj0iaHR0cDovL2Z0cC5zdW5ldC5zZS9wdWIvbmV0d29yay9tb25pdG9yaW5nL2V0aGVyZWFsL3JwbXMvIj5Td2VkZW48L2E+CjwvcD4KPHA+CkZUUDoKPGEgaHJlZj0iZnRwOi8vZnRwLmV0aGVyZWFsLmNvbS9wdWIvZXRoZXJlYWwvcnBtcy8iPk1haW4gc2l0ZTwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLnBsYW5ldG1pcnJvci5jb20vcHViL2V0aGVyZWFsL3JwbXMvIj5BdXN0cmFsaWE8L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5taXJyb3JzLndpcmV0YXBwZWQubmV0L3B1Yi9zZWN1cml0eS9wYWNrZXQtY2FwdHVyZS9ldGhlcmVhbC9ycG1zLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJmdHA6Ly9nZC50dXdpZW4uYWMuYXQvaW5mb3N5cy9zZWN1cml0eS9ldGhlcmVhbC9ycG1zLyI+QXVzdHJpYTwvYT4KPGEgaHJlZj0iZnRwOi8vbmV0bWlycm9yLm9yZy9mdHAuZXRoZXJlYWwuY29tL3JwbXMvIj5HZXJtYW55PC9hPgo8YSBocmVmPSJmdHA6Ly9mdHAuYXlhbXVyYS5vcmcvcHViL2V0aGVyZWFsL3JwbXMvIj5KYXBhbjwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLmF6Yy51YW0ubXgvbWlycm9ycy9ldGhlcmVhbC9ycG1zLyI+TWV4aWNvPC9hPgo8YSBocmVmPSJmdHA6Ly9mdHAuc3VuZXQuc2UvcHViL25ldHdvcmsvbW9uaXRvcmluZy9ldGhlcmVhbC9ycG1zLyI+U3dlZGVuPC9hPgo8L3A+CjxoND5Tb2xhcmlzIFBhY2thZ2VzPC9oND4KPHA+CkhUVFA6CjxhIGhyZWY9Imh0dHA6Ly93d3cuZXRoZXJlYWwuY29tL2Rpc3RyaWJ1dGlvbi9zb2xhcmlzLyI+TWFpbiBzaXRlPC9hPgo8YSBocmVmPSJodHRwOi8vZXRoZXJlYWwucGxhbmV0bWlycm9yLmNvbS9kaXN0cmlidXRpb24vc29sYXJpcy8iPkF1c3RyYWxpYTwvYT4KPGEgaHJlZj0iaHR0cDovL3d3dy5taXJyb3JzLndpcmV0YXBwZWQubmV0L3NlY3VyaXR5L3BhY2tldC1jYXB0dXJlL2V0aGVyZWFsL3NvbGFyaXMvIj5BdXN0cmFsaWE8L2E+CjxhIGhyZWY9Imh0dHA6Ly9uZXRtaXJyb3Iub3JnL21pcnJvci9mdHAuZXRoZXJlYWwuY29tL3NvbGFyaXMvIj5HZXJtYW55PC9hPgo8YSBocmVmPSJodHRwOi8vZXRoZXJlYWwubmV0YXJjLmpwL2Rpc3RyaWJ1dGlvbi9zb2xhcmlzLyI+SmFwYW48L2E+CjxhIGhyZWY9Imh0dHA6Ly9ldGhlcmVhbC5zZWN1d2l6LmNvbS9kaXN0cmlidXRpb24vc29sYXJpcy8iPktvcmVhPC9hPgo8YSBocmVmPSJodHRwOi8vZXRoZXJlYWwuMG5pMG4ub3JnL2Rpc3RyaWJ1dGlvbi9zb2xhcmlzLyI+TWFsYXlzaWE8L2E+CjxhIGhyZWY9Imh0dHA6Ly9mdHAuc3VuZXQuc2UvcHViL25ldHdvcmsvbW9uaXRvcmluZy9ldGhlcmVhbC9zb2xhcmlzLyI+U3dlZGVuPC9hPgo8YSBocmVmPSJodHRwOi8vc291cmNlZm9yZ2UubmV0L3Byb2plY3Qvc2hvd2ZpbGVzLnBocD9ncm91cF9pZD0yNTUiPlNvdXJjZUZvcmdlPC9hPgo8L3A+CjxwPgpGVFA6CjxhIGhyZWY9ImZ0cDovL2Z0cC5ldGhlcmVhbC5jb20vcHViL2V0aGVyZWFsL3NvbGFyaXMvIj5NYWluIHNpdGU8L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5wbGFuZXRtaXJyb3IuY29tL3B1Yi9ldGhlcmVhbC9zb2xhcmlzLyI+QXVzdHJhbGlhPC9hPgo8YSBocmVmPSJmdHA6Ly9mdHAubWlycm9ycy53aXJldGFwcGVkLm5ldC9wdWIvc2VjdXJpdHkvcGFja2V0LWNhcHR1cmUvZXRoZXJlYWwvc29sYXJpcy8iPkF1c3RyYWxpYTwvYT4KPGEgaHJlZj0iZnRwOi8vZ2QudHV3aWVuLmFjLmF0L2luZm9zeXMvc2VjdXJpdHkvZXRoZXJlYWwvc29sYXJpcy8iPkF1c3RyaWE8L2E+CjxhIGhyZWY9ImZ0cDovL25ldG1pcnJvci5vcmcvZnRwLmV0aGVyZWFsLmNvbS9zb2xhcmlzLyI+R2VybWFueTwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLmF5YW11cmEub3JnL3B1Yi9ldGhlcmVhbC9zb2xhcmlzLyI+SmFwYW48L2E+CjxhIGhyZWY9ImZ0cDovL2Z0cC5hemMudWFtLm14L21pcnJvcnMvZXRoZXJlYWwvc29sYXJpcy8iPk1leGljbzwvYT4KPGEgaHJlZj0iZnRwOi8vZnRwLnN1bmV0LnNlL3B1Yi9uZXR3b3JrL21vbml0b3JpbmcvZXRoZXJlYWwvc29sYXJpcy8iPlN3ZWRlbjwvYT4KPC9wPgo8L2Rpdj4KPGRpdiBjbGFzcz0iYmxvY2siPgogIDxoMiBjbGFzcz0iaGVhZGVybGluZSIgaWQ9Im90aGVycGxhdCI+T3RoZXIgUGxhdGZvcm1zPC9oMj4KPHA+CiAgQmluYXJ5IGRpc3RyaWJ1dGlvbnMgYW5kIHJlYWR5LXRvLWNvbXBpbGUgcGFja2FnZXMgYXJlIGF2YWlsYWJsZSBmb3IKICBtb3N0IHBsYXRmb3Jtcy4gUGxlYXNlIG5vdGUgdGhlc2UgcGFja2FnZXMgbWF5IGRlcGVuZCBvbiBleHRlcm5hbAogIGxpYnJhcmllcyBpbmNsdWRpbmcgR0xpYi9HVEsrLCBsaWJwY2FwLCBOZXQtU05NUCwgUENSRSwgYW5kIEdOVSBBRE5TLgogIFlvdSBtYXkgaGF2ZSB0byBkb3dubG9hZCBhbmQgaW5zdGFsbCB0aGVtIGJlZm9yZSBpbnN0YWxsaW5nIEV0aGVyZWFsLgo8L3A+Cjx0YWJsZSBjZWxsc3BhY2luZz0iMSIgY2VsbHBhZGRpbmc9IjIiIGJvcmRlcj0iMCIgc3VtbWFyeT0iIj4KPHRyIGJnY29sb3I9IiNjY2NjOTkiPgogIDx0aD5QbGF0Zm9ybTwvdGg+CiAgPHRoPkxvY2F0aW9uKHMpPC90aD4KPC90cj4KPHRyPgogIDx0ZCB2YWxpZ249InRvcCI+QXBwbGUgQ29tcHV0ZXI6PGJyPk1hYyBPUyBYPC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iaHR0cDovL2Zpbmsuc291cmNlZm9yZ2UubmV0L3BkYi9wYWNrYWdlLnBocC9ldGhlcmVhbCI+RmluayBQcm9qZWN0PC9hPgogICAgPGEgaHJlZj0iaHR0cDovL2RhcndpbnBvcnRzLm9wZW5kYXJ3aW4ub3JnIj5EYXJ3aW5Qb3J0czwvYT4KPC90ZD4KPC90cj4KPHRyIGNsYXNzPSJldmVuIj4KICA8dGQgdmFsaWduPSJ0b3AiPkJlIChQYWxtPyk6PGJyPkJlT1M8L3RkPgogIDx0ZCB2YWxpZ249InRvcCI+CiAgICA8YSBocmVmPSJodHRwOi8vd3d3LmJlYml0cy5jb20vYXBwLzI5NzkiPkJlQml0czwvYT4KPC90ZD4KPC90cj4KPHRyPgogIDx0ZCB2YWxpZ249InRvcCI+RGViaWFuOjxicj5EZWJpYW4gR05VL0xpbnV4PC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iaHR0cDovL3BhY2thZ2VzLmRlYmlhbi5vcmcvc3RhYmxlL25ldC9ldGhlcmVhbCI+c3RhYmxlPC9hPiwKICAgIDxhIGhyZWY9Imh0dHA6Ly9wYWNrYWdlcy5kZWJpYW4ub3JnL3Rlc3RpbmcvbmV0L2V0aGVyZWFsIj50ZXN0aW5nPC9hPiwKICAgIDxhIGhyZWY9Imh0dHA6Ly9wYWNrYWdlcy5kZWJpYW4ub3JnL3Vuc3RhYmxlL25ldC9ldGhlcmVhbCI+dW5zdGFibGU8L2E+CjwvdGQ+CjwvdHI+Cjx0ciBjbGFzcz0iZXZlbiI+CiAgPHRkIHZhbGlnbj0idG9wIj5UaGUgRnJlZUJTRCBQcm9qZWN0Ojxicj5GcmVlQlNEPC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iaHR0cDovL3d3dy5mcmVlYnNkLm9yZy9jZ2kvcG9ydHMuY2dpP3F1ZXJ5PWV0aGVyZWFsJnN0eXBlPWFsbCI+cG9ydHM8L2E+CjwvdGQ+CjwvdHI+Cjx0cj4KICA8dGQgdmFsaWduPSJ0b3AiPkdlbnRvbyBUZWNobm9sb2dpZXM6PGJyPkdlbnRvbyBMaW51eDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cuZ2VudG9vLm9yZy9wYWNrYWdlcy9uZXQtYW5hbHl6ZXIvZXRoZXJlYWwuaHRtbCI+cG9ydGFnZTwvYT4KPC90ZD4KPC90cj4KPHRyIGNsYXNzPSJldmVuIj4KICA8dGQgdmFsaWduPSJ0b3AiPkhQOjxicj5UcnU2NCBVbml4PC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iZnRwOi8vZnRwLnRoZXdyaXR0ZW53b3JkLmNvbS9wYWNrYWdlcy9ieS1uYW1lL2V0aGVyZWFsLTAuOS4xNi8iPlRoZSBXcml0dGVuIFdvcmQgKDQuMGQsIDUuMSk8L2E+PHN1cGVyPjxzbWFsbD4xPC9zbWFsbD48L3N1cGVyPgo8L3RkPgo8L3RyPgo8dHI+CiAgPHRkIHZhbGlnbj0idG9wIj5IUDo8YnI+SFAtVVg8L3RkPgogIDx0ZCB2YWxpZ249InRvcCI+CiAgICA8YSBocmVmPSJodHRwOi8vaHB1eC5jb25uZWN0Lm9yZy51ay9ocHBkL2hwdXgvR3RrL0FwcGxpY2F0aW9ucy8iPlVLPC9hPiwKICAgIDxhIGhyZWY9Imh0dHA6Ly9ocHV4LmFza25ldC5kZS9ocHBkL2hwdXgvR3RrL0FwcGxpY2F0aW9ucy8iPkdlcm1hbnk8L2E+LAogICAgPGEgaHJlZj0iaHR0cDovL2hwdXgudG4udHVkZWxmdC5ubC9ocHBkL2hwdXgvR3RrL0FwcGxpY2F0aW9ucy8iPk5ldGhlcmxhbmRzPC9hPiwKICAgIDxhIGhyZWY9Imh0dHA6Ly9ocHV4LmNzLnV0YWguZWR1L2hwcGQvaHB1eC9HdGsvQXBwbGljYXRpb25zLyI+VVM8L2E+LAogICAgPGEgaHJlZj0iaHR0cDovL2hwdXguZWUudWFsYmVydGEuY2EvaHBwZC9ocHV4L0d0ay9BcHBsaWNhdGlvbnMvIj5DYW5hZGE8L2E+LAogICAgPGEgaHJlZj0iaHR0cDovL2hwdXgucGV0ZWNoLmFjLnphLy9ocHBkL2hwdXgvR3RrL0FwcGxpY2F0aW9ucy8iPlNvdXRoJm5ic3A7QWZyaWNhPC9hPgogICAgPGJyPihtb3JlIG1pcnJvcnMgYXJlIGxpc3RlZCBvbiBlYWNoIHNpdGUncyBob21lIHBhZ2UpLDxicj4KICAgIDxhIGhyZWY9ImZ0cDovL2Z0cC50aGV3cml0dGVud29yZC5jb20vcGFja2FnZXMvYnktbmFtZS9ldGhlcmVhbC0wLjkuMTYvIj5UaGUgV3JpdHRlbiBXb3JkICgxMC4yMCwgMTEuMDAsIDExLjExKTwvYT48c3VwZXI+PHNtYWxsPjE8L3NtYWxsPjwvc3VwZXI+CjwvdGQ+CjwvdHI+Cjx0ciBjbGFzcz0iZXZlbiI+CiAgPHRkIHZhbGlnbj0idG9wIj5JQk06PGJyPkFJWDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cuYnVsbGZyZWV3YXJlLmNvbS8iPkJ1bGwgYXJjaGl2ZTwvYT48YnI+CiAgICA8YSBocmVmPSJodHRwOi8vZnRwLnVuaXZpZS5hYy5hdC9haXgvIj5WaWVubmEgVW5pdmVyc2l0eSBtaXJyb3I8L2E+PGJyPgogICAgPGEgaHJlZj0iaHR0cDovL2FpeHBkc2xpYi5zZWFzLnVjbGEuZWR1L2J1bGwuaHRtbCI+VUNMQSBtaXJyb3I8L2E+CjwvdGQ+CjwvdHI+CiAgPCEtLSBBc2hsZXkgRyBDaGFsb25lciA8Y3N1d2YgW2F0XSBkY3Mud2Fyd2ljay5hYy51az4gLS0+Cjx0cj4KICA8dGQgdmFsaWduPSJ0b3AiPklCTTo8YnI+Uy8zOTAgTGludXggKFJlZCBIYXQgNy4yKTwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cuZGNzLndhcndpY2suYWMudWsvfmNzdXdmL1JQTXMvIj5Bc2hsZXkgQ2hhbG9uZXI8L2E+PGJyPgo8L3RkPgo8L3RyPgo8dHIgY2xhc3M9ImV2ZW4iPgogIDx0ZCB2YWxpZ249InRvcCI+TWFuZHJha2VTb2Z0Ojxicj5NYW5kcmFrZSBMaW51eDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cubGludXgtbWFuZHJha2UuY29tL2VuL2Nvb2tlcmRldmVsLnBocDMiPkNvb2tlcjwvYT4KICAgIChpbiB0aGUgY29udHJpYiBzZWN0aW9uKQo8L3RkPgo8L3RyPgo8dHI+CiAgPHRkIHZhbGlnbj0idG9wIj5NaWNyb3NvZnQ6PGJyPldpbmRvd3MgKEludGVsLCAzMi1iaXQpPC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iaHR0cDovL3d3dy5ldGhlcmVhbC5jb20vZGlzdHJpYnV0aW9uL3dpbjMyIj5sb2NhbCBhcmNoaXZlPC9hPjxicj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cub3Blbnh0cmEuY29tL3Byb2R1Y3RzL2V0aGVyZWFsX3h0cmEuaHRtIj5PUEVORVhUUkE8L2E+CjwvdGQ+CjwvdHI+Cjx0ciBjbGFzcz0iZXZlbiI+CiAgPHRkIHZhbGlnbj0idG9wIj5OZXRCU0QgRm91bmRhdGlvbjo8YnI+TmV0QlNEPC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iZnRwOi8vZnRwLm5ldGJzZC5vcmcvcHViL05ldEJTRC9wYWNrYWdlcy9wa2dzcmMvbmV0L2V0aGVyZWFsL1JFQURNRS5odG1sIj5wYWNrYWdlczwvYT4KPC90ZD4KPC90cj4KPHRyPgogIDx0ZCB2YWxpZ249InRvcCI+T3BlbkJTRDo8YnI+T3BlbkJTRDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cub3BlbmJzZC5vcmcvY2dpLWJpbi9jdnN3ZWIvcG9ydHMvbmV0L2V0aGVyZWFsLyI+cG9ydHM8L2E+CjwvdGQ+CjwvdHI+Cjx0ciBjbGFzcz0iZXZlbiI+CiAgPHRkIHZhbGlnbj0idG9wIj5QTEQgVGVhbTo8YnI+UExEIExpbnV4PC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iZnRwOi8vZnRwLnBsZC1saW51eC5vcmcvZGlzdHMvcmEiPkZUUCBzaXRlPC9hPgo8L3RkPgo8L3RyPgo8dHI+CiAgPHRkIHZhbGlnbj0idG9wIj5SZWQgSGF0Ojxicj5SZWQgSGF0IExpbnV4PC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iaHR0cDovL3JwbWZpbmQubmV0L2xpbnV4L1JQTS9FQnlOYW1lLmh0bWwiPlJQTUZpbmQ8L2E+IChyZXF1aXJlcyBnbGliYyk8YnI+CiAgICA8YSBocmVmPSJmdHA6Ly9mdHAuZmFsc2Vob3BlLmNvbS9ob21lL2dvbWV6L2V0aGVyZWFsLyI+SGVucmkgR29tZXo8L2E+PGJyPgogICAgPGEgaHJlZj0iZnRwOi8vZnRwLnRoZXdyaXR0ZW53b3JkLmNvbS9wYWNrYWdlcy9ieS1uYW1lL2V0aGVyZWFsLTAuOS4xNi8iPlRoZSBXcml0dGVuIFdvcmQgKDcuMSk8L2E+PHN1cGVyPjxzbWFsbD4xPC9zbWFsbD48L3N1cGVyPjxicj4KICAgIDxhIGhyZWY9ImZ0cDovL2Z0cC5ldGhlcmVhbC5jb20vcHViL2V0aGVyZWFsL3JwbXMvIj5sb2NhbCBhcmNoaXZlPC9hPjxicj4KPC90ZD4KPC90cj4KPHRyIGNsYXNzPSJldmVuIj4KICA8dGQgdmFsaWduPSJ0b3AiPlJPQ0sgTGludXg6PGJyPlJPQ0sgTGludXg8L3RkPgogIDx0ZCB2YWxpZ249InRvcCI+CiAgICA8YSBocmVmPSJodHRwOi8vd3d3LnJvY2tsaW51eC5vcmcvc291cmNlcy9wYWNrYWdlL3RzYS9ldGhlcmVhbC8iPnBhY2thZ2U8L2E+PGJyPgo8L3RkPgo8L3RyPgo8dHI+CiAgPHRkIHZhbGlnbj0idG9wIj5TQ08gKGZvcm1lcmx5IENhbGRlcmEpOjxicj5Vbml4V2FyZS9PcGVuVW5peDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cuc2NvLmNvbS9za3Vua3dhcmUvIj5Ta3Vua3dhcmU8L2E+OgogICAgPGEgaHJlZj0iZnRwOi8vZnRwMi5jYWxkZXJhLmNvbS9wdWIvc2t1bmt3YXJlL3V3Ny9uZXQvZXRoZXJlYWwvIj5Vbml4V2FyZSA3PC9hPgogICAgPGEgaHJlZj0iZnRwOi8vZnRwMi5jYWxkZXJhLmNvbS9wdWIvc2t1bmt3YXJlL291OC9uZXQvZXRoZXJlYWwvIj5PcGVuIFVOSVggODwvYT4KPC90ZD4KPC90cj4KPHRyIGNsYXNzPSJldmVuIj4KICA8dGQgdmFsaWduPSJ0b3AiPlNHSTo8YnI+SXJpeDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9ImZ0cDovL2Z0cC50aGV3cml0dGVud29yZC5jb20vcGFja2FnZXMvYnktbmFtZS9ldGhlcmVhbC0wLjkuMTYvIj5UaGUgV3JpdHRlbiBXb3JkICg2LjUpPC9hPjxzdXBlcj48c21hbGw+MTwvc21hbGw+PC9zdXBlcj48YnI+CiAgICA8YSBocmVmPSJodHRwOi8vZnJlZXdhcmUuc2dpLmNvbS9pbmRleC1ieS1hbHBoYS5odG1sIj5TR0kgRnJlZXdhcmU8L2E+CjwvdGQ+CjwvdHI+Cjx0cj4KICA8dGQgdmFsaWduPSJ0b3AiPlNsYWNrd2FyZSBMaW51eDo8YnI+U2xhY2t3YXJlIExpbnV4PC90ZD4KICA8dGQgdmFsaWduPSJ0b3AiPgogICAgPGEgaHJlZj0iaHR0cDovL3d3dy5saW51eHBhY2thZ2VzLm5ldC9zZWFyY2hfdmlldy5waHA/Ynk9bmFtZSZuYW1lPWV0aGVyZWFsJnZlcj0iPkxpbnV4IFBhY2thZ2VzPC9hPgo8L3RkPgo8L3RyPgo8dHIgY2xhc3M9ImV2ZW4iPgogIDx0ZCB2YWxpZ249InRvcCI+U3VuIE1pY3Jvc3lzdGVtczo8YnI+U29sYXJpcy9JbnRlbDwvdGQ+CiAgPHRkIHZhbGlnbj0idG9wIj4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cuc3VuLmNvbS9zb2xhcmlzL2ZyZWV3YXJlLmh0bWwiPlNvbGFyaXMgMDEvMDEgdXBkYXRlPC9hPiAodW5zdXBwb3J0ZWQpCjwvdGQ+CjwvdHI+Cjx0cj4KICA8dGQgdmFsaWduPSJ0b3AiPlN1biBNaWNyb3N5c3RlbXM6PGJyPlNvbGFyaXMvU1BBUkM8L3RkPgogIDx0ZCB2YWxpZ249InRvcCI+CiAgICA8YSBocmVmPSJodHRwOi8vd3d3LmV0aGVyZWFsLmNvbS9kaXN0cmlidXRpb24vc29sYXJpcy8iPmxvY2FsIGFyY2hpdmUgKDgsIDkpPC9hPjxicj4KICAgIDxhIGhyZWY9ImZ0cDovL2Z0cC50aGV3cml0dGVud29yZC5jb20vcGFja2FnZXMvYnktbmFtZS9ldGhlcmVhbC0wLjkuMTYvIj5UaGUgV3JpdHRlbiBXb3JkICgyLjUuMSAtIDkpPC9hPjxzdXBlcj48c21hbGw+MTwvc21hbGw+PC9zdXBlcj48YnI+CiAgICA8YSBocmVmPSJodHRwOi8vd3d3LnN1bmZyZWV3YXJlLmNvbS8iPlN1bmZyZWV3YXJlLmNvbSAoNywgOCk8L2E+PGJyPgogICAgPGEgaHJlZj0iaHR0cDovL3d3dy5zdW4uY29tL3NvbGFyaXMvZnJlZXdhcmUvaW5kZXguaHRtbCI+U29sYXJpcyA4IGFuZCA5IENvbXBhbmlvbiBTb2Z0d2FyZSBDRHM8L2E+ICh1bnN1cHBvcnRlZCkKPC90ZD4KPC90cj4KPHRyIGNsYXNzPSJldmVuIj4KICA8dGQgdmFsaWduPSJ0b3AiPlN1U0U6PGJyPlN1U0UgTGludXg8L3RkPgogIDx0ZCB2YWxpZ249InRvcCI+CiAgICA8YSBocmVmPSJmdHA6Ly9mdHAuc3VzZS5jb20vcHViL3N1c2UvIj5TdVNFIEZUUCBzaXRlPC9hPi4KICAgIDxhIGhyZWY9Imh0dHA6Ly93d3cuc3VzZS5jb20vdXMvcHJpdmF0ZS9kb3dubG9hZC9mdHAvaW50X21pcnJvcnMuaHRtbCI+TWlycm9yczwvYT4gYXJlIGFsc28gYXZhaWxhYmxlLgo8L3RkPgo8L3RyPgo8L3RhYmxlPgo8cD4KICBJZiB5b3Uga25vdyBvZiBhbnkgYmluYXJ5IGRpc3RyaWJ1dGlvbiBub3QgbGlzdGVkIGhlcmUsIHBsZWFzZSBzZW5kIG1haWwKICB0bwogIDxhIGhyZWY9Im1haWx0bzpldGhlcmVhbC13ZWJbQVRdZXRoZXJlYWwuY29tIj5ldGhlcmVhbC13ZWJbQVRdZXRoZXJlYWwuY29tPC9hPgouCjwvcD4KPHAgY2xhc3M9ImZvb3Rub3RlIj4KICBbMV0gRWFjaCBFdGhlcmVhbCBwYWNrYWdlIHByb2R1Y2VkIGJ5CiAgPGEgaHJlZj0iaHR0cDovL3d3dy50aGV3cml0dGVud29yZC5jb20iPlRoZSBXcml0dGVuIFdvcmQ8L2E+IGRlcGVuZHMgb24gdGhlCiAgPGEgaHJlZj0iZnRwOi8vZnRwLnRoZXdyaXR0ZW53b3JkLmNvbS9wYWNrYWdlcy9ieS1uYW1lL3psaWItMS4xLjQvIj56bGliPC9hPiwKICA8YSBocmVmPSJmdHA6Ly9mdHAudGhld3JpdHRlbndvcmQuY29tL3BhY2thZ2VzL2J5LW5hbWUvZ2xpYi0xLjIuMTAvIj5HbGliPC9hPiwKICA8YSBocmVmPSJmdHA6Ly9mdHAudGhld3JpdHRlbndvcmQuY29tL3BhY2thZ2VzL2J5LW5hbWUvZ3RrKy0xLjIuMTAvIj5HVEsrPC9hPiwKICA8YSBocmVmPSJmdHA6Ly9mdHAudGhld3JpdHRlbndvcmQuY29tL3BhY2thZ2VzL2J5LW5hbWUvcGVybC01LjYuMS8iPlBlcmw8L2E+LCBhbmQKICA8YSBocmVmPSJmdHA6Ly9mdHAudGhld3JpdHRlbndvcmQuY29tL3BhY2thZ2VzL2J5LW5hbWUvbmV0LXNubXAtNS4wLjkvIj5OZXQtU05NUDwvYT4KICBwYWNrYWdlcy4KICBQbGVhc2UgcmVmZXIgdG8gVGhlIFdyaXR0ZW4gV29yZCdzCiAgPGEgaHJlZj0iZnRwOi8vZnRwLnRoZXdyaXR0ZW53b3JkLmNvbS9wYWNrYWdlcy9JTlNUQUxMLnBkZiI+ZG9jdW1lbnRhdGlvbjwvYT4KICBmb3IgaW5zdGFsbGF0aW9uIGluc3RydWN0aW9ucy4KICBQbGVhc2UgZG8gbm90IGNhbGwgVGhlIFdyaXR0ZW4gV29yZCBmb3Igc3VwcG9ydC4gRW1haWwKICA8YSBocmVmPSJtYWlsdG86ZnJlZS1zdXBwb3J0W0FUXXRoZXdyaXR0ZW53b3JkLmNvbSI+ZnJlZS1zdXBwb3J0W0FUXXRoZXdyaXR0ZW53b3JkLmNvbTwvYT4KICB3aXRoIHF1ZXN0aW9ucy4KPC9wPgo8L2Rpdj4KPGRpdiBjbGFzcz0iYmxvY2siPgogIDxoMiBjbGFzcz0iaGVhZGVybGluZSIgaWQ9Im90aGVyZG93biI+T3RoZXIgRG93bmxvYWRzPC9oMj4KPGg0PlNhbXBsZSBDYXB0dXJlczwvaDQ+CjxwPgogIEEgbWVuYWdlcmllIG9mIGNhcHR1cmUgZmlsZXMgaXMgYXZhaWxhYmxlIG9uIG91cgogIDxhIGhyZWY9Ii4uL3NhbXBsZS8iPnNhbXBsZSBjYXB0dXJlczwvYT4gcGFnZS4KPC9wPgo8aDQ+RG9jdW1lbnRhdGlvbjwvaDQ+CjxwPgogIEEgUERGIHZlcnNpb24gb2YgdGhlIEV0aGVyZWFsIFVzZXIncyBHdWlkZSBpcyBhdmFpbGFibGUgaW4gdGhlCiAgPGEgaHJlZj0iLi4vZG9jcy8jcmVzb3VyY2VzIj5kb2N1bWVudGF0aW9uPC9hPiBwYWdlLgo8L2Rpdj4KPGRpdiBjbGFzcz0iYmxvY2siPgogIDxoMiBjbGFzcz0iaGVhZGVybGluZSIgaWQ9ImxlZ2FsIj5MZWdhbCBOb3RpY2VzPC9oMj4KPHA+CkFJWCBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIEludGVybmF0aW9uYWwgQnVzaW5lc3MgTWFjaGluZXMsIEluYy4KVHJ1NjQgaXMgYSByZWdpc3RlcmVkIHRyYWRlbWFyayBvZiBDb21wYXEgQ29tcHV0ZXIgQ29ycG9yYXRpb24uCkRlYmlhbiBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIFNvZnR3YXJlIEluIFRoZSBQdWJsaWMgSW50ZXJlc3QsIEluYy4KRnJlZUJTRCBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIFdhbG51dCBDcmVlayBDRFJPTSwgSW5jLgpIUC1VWCBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIEhld2xldHQtUGFja2FyZCBDb21wYW55LgpJcml4IGlzIGEgcmVnaXN0ZXJlZCB0cmFkZW1hcmsgb2YgU2lsaWNvbiBHcmFwaGljcywgSW5jLgpMaW51eFBQQyBpcyBhIHRyYWRlbWFyayBvZiBKZWZmIENhcnIuCk1hYyBPUyBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIEFwcGxlIENvbXB1dGVyLCBJbmMuCk5ldEJTRCBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIHRoZSBOZXRCU0QgRm91bmRhdGlvbi4KUmVkIEhhdCBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIFJlZCBIYXQsIEluYy4KTGludXggaXMgYSByZWdpc3RlcmVkIHRyYWRlbWFyayBvZiBMaW51cyBUb3J2YWxkcy4KU0NPIGFuZCBVbml4d2FyZSBhcmUgcmVnaXN0ZXJlZCB0cmFkZW1hcmtzIG9mIFNhbnRhIENydXogT3BlcmF0aW9uLCBJbmMuClNsYWNrd2FyZSBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIFBhdHJpY2sgVm9sa2VyZGluZy4KU29sYXJpcyBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIFN1biBNaWNyb3N5c3RlbXMsIEluYy4KU3VTRSBpcyBhIHJlZ2lzdGVyZWQgdHJhZGVtYXJrIG9mIFN1U0UgQUcuCk1pY3Jvc29mdCwgV2luZG93cywgV2luZG93cyA5NSwgV2luZG93cyA5OCwgV2luZG93cyBNRSwgV2luZG93cyBOVCwKV2luZG93cyAyMDAwLCBhbmQgV2luZG93cyBYUCBhcmUgcmVnaXN0ZXJlZCB0cmFkZW1hcmtzIG9mIE1pY3Jvc29mdCwKSW5jLgpBbGwgb3RoZXIgdHJhZGVtYXJrcyBvbiB0aGlzIHNpdGUgYXJlIHByb3BlcnR5IG9mIHRoZWlyIHJlc3BlY3RpdmUgb3duZXJzLgo8L3A+CjwvZGl2Pgo8ZGl2IGNsYXNzPSJmb290ZXIiPgogIFBsZWFzZSBzZW5kIHN1cHBvcnQgcXVlc3Rpb25zIGFib3V0IEV0aGVyZWFsIHRvIHRoZQogIDxhIGhyZWY9Im1haWx0bzpldGhlcmVhbC11c2Vyc1tBVF1ldGhlcmVhbC5jb20iPmV0aGVyZWFsLXVzZXJzW0FUXWV0aGVyZWFsLmNvbTwvYT4KICAgIG1haWxpbmcgbGlzdC48YnI+CiAgRm9yIGNvcnJlY3Rpb25zL2FkZGl0aW9ucy9zdWdnZXN0aW9ucyBmb3IgdGhpcyB3ZWIgcGFnZSAoYW5kIDxiPm5vdDwvYj4gRXRoZXJlYWwKICBzdXBwb3J0IHF1ZXN0aW9ucyksIHBsZWFzZSBzZW5kIGVtYWlsIHRvCiAgPGEgaHJlZj0ibWFpbHRvOmV0aGVyZWFsLXdlYltBVF1ldGhlcmVhbC5jb20iPmV0aGVyZWFsLXdlYltBVF1ldGhlcmVhbC5jb208L2E+Ci48YnI+CiAgTGFzdCBtb2RpZmllZDogVHVlLCBBcHJpbCAyMCAyMDA0Lgo8L2Rpdj4KPC9ib2R5Pgo8L2h0bWw+Cg==",
      "file": "download.html",
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
