// Check if the browser supports Web Workers
if (window.Worker) {
  const worker = new Worker("worker.js");

  // Event listener for file input change
  document
    .getElementById("fileInput")
    .addEventListener("change", function (event) {
      const file = event.target.files[0];
      if (file) {
        worker.postMessage({ type: "process", file: file });
      }
    });

  // Event listener to receive messages from the worker
  worker.onmessage = function (event) {
    // document.getElementById("output").innerText = event.data;
    const data = event.data;

    if (data.type === "init") {
      document.getElementById("output").innerText = "Wiregasm initialized.";
    } else if (data.type === "error") {
      document.getElementById("output").innerText = data.error;
    } else if (data.type === "status") {
      document.getElementById("output").innerText = data.status;
    } else if (data.type === "processed" && data.data.code === 0) {
      document.getElementById("fileName").innerText = data.name;
      document.getElementById("fileSize").innerText =
        data.data.summary.file_length;
      document.getElementById("fileType").innerText =
        data.data.summary.file_type;
      // fileEncapType
      document.getElementById("fileEncapType").innerText =
        data.data.summary.file_encap_type;
      document.getElementById("filePackets").innerText =
        data.data.summary.packet_count;

      document.getElementById("captureDetails").hidden = false;
    } else {
      console.log(data);
    }
  };

  // Error handling
  worker.onerror = function (error) {
    console.error("Worker error:", error);
    document.getElementById("output").innerText =
      "Error occurred in the worker.";
  };
} else {
  document.getElementById("output").innerText =
    "Your browser does not support Web Workers.";
}
