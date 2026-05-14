const presets = {
  "Standard CBC Walkthrough": {
    engine: "CBC",
    keyHex: "00112233445566778899aabbccddeeff",
    ivHex: "0f0e0d0c0b0a09080706050403020100",
    aad: "",
    plaintext: "Meet at 5 PM by the library steps.",
  },
  "Standard GCM Integrity Demo": {
    engine: "GCM",
    keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ivHex: "1a1b1c1d1e1f202122232425",
    aad: "attendance-sheet",
    plaintext: "GCM adds authentication so tampering is detectable.",
  },
  "Rijndael Trace Walkthrough": {
    engine: "TRACE",
    keyHex: "000102030405060708090a0b0c0d0e0f",
    ivHex: "0f0e0d0c0b0a09080706050403020100",
    aad: "",
    plaintext: "Load trace.json from the Tkinter exporter to present Rijndael round steps.",
  },
};

const els = {
  presetSelect: document.querySelector("#presetSelect"),
  loadPresetButton: document.querySelector("#loadPresetButton"),
  engineSelect: document.querySelector("#engineSelect"),
  keyInput: document.querySelector("#keyInput"),
  ivInput: document.querySelector("#ivInput"),
  aadInput: document.querySelector("#aadInput"),
  plaintextInput: document.querySelector("#plaintextInput"),
  encryptButton: document.querySelector("#encryptButton"),
  decryptButton: document.querySelector("#decryptButton"),
  patternButton: document.querySelector("#patternButton"),
  traceFileInput: document.querySelector("#traceFileInput"),
  packetOutput: document.querySelector("#packetOutput"),
  decryptedOutput: document.querySelector("#decryptedOutput"),
  notesOutput: document.querySelector("#notesOutput"),
  traceOutput: document.querySelector("#traceOutput"),
};

let currentPacket = null;
let loadedTrace = null;

function hexToBytes(hex) {
  const clean = hex.trim();
  if (!clean || clean.length % 2 !== 0) {
    throw new Error("Hex input must be non-empty and have even length.");
  }

  const bytes = new Uint8Array(clean.length / 2);
  for (let index = 0; index < clean.length; index += 2) {
    bytes[index / 2] = Number.parseInt(clean.slice(index, index + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(text) {
  const binary = atob(text);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function textToBytes(text) {
  return new TextEncoder().encode(text);
}

function bytesToText(bytes) {
  return new TextDecoder().decode(bytes);
}

function pkcs7Pad(bytes, blockSize = 16) {
  const padLength = blockSize - (bytes.length % blockSize || blockSize % blockSize);
  const output = new Uint8Array(bytes.length + padLength);
  output.set(bytes);
  output.fill(padLength, bytes.length);
  return output;
}

function pkcs7Unpad(bytes) {
  const padLength = bytes[bytes.length - 1];
  if (!padLength || padLength > 16) {
    throw new Error("Invalid PKCS#7 padding.");
  }
  return bytes.slice(0, bytes.length - padLength);
}

async function importKey(rawKey, algorithm) {
  return crypto.subtle.importKey("raw", rawKey, algorithm, false, ["encrypt", "decrypt"]);
}

async function encryptCurrent() {
  const engine = els.engineSelect.value;
  if (engine === "TRACE") {
    currentPacket = {
      engine: "Rijndael Trace Viewer",
      message: "Load trace.json exported from the Tkinter app to present round-by-round state changes.",
    };
    renderOutputs();
    return;
  }

  const keyBytes = hexToBytes(els.keyInput.value);
  const ivBytes = hexToBytes(els.ivInput.value);
  const plaintextBytes = textToBytes(els.plaintextInput.value);

  if (engine === "CBC") {
    const key = await importKey(keyBytes, "AES-CBC");
    const padded = pkcs7Pad(plaintextBytes, 16);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, padded)
    );

    currentPacket = {
      engine: "Standard Browser Demo",
      mode: "CBC",
      iv: bytesToBase64(ivBytes),
      ciphertext: bytesToBase64(ciphertext),
      tag: null,
      aad: null,
    };
  } else {
    const aadBytes = textToBytes(els.aadInput.value);
    const key = await importKey(keyBytes, "AES-GCM");
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivBytes, additionalData: aadBytes, tagLength: 128 },
        key,
        plaintextBytes
      )
    );

    const tag = encrypted.slice(encrypted.length - 16);
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    currentPacket = {
      engine: "Standard Browser Demo",
      mode: "GCM",
      iv: bytesToBase64(ivBytes),
      ciphertext: bytesToBase64(ciphertext),
      tag: bytesToBase64(tag),
      aad: els.aadInput.value ? bytesToBase64(aadBytes) : null,
    };
  }

  renderOutputs();
}

async function decryptCurrent() {
  if (!currentPacket || !currentPacket.mode) {
    throw new Error("Encrypt first or load a valid packet into the demo.");
  }

  const keyBytes = hexToBytes(els.keyInput.value);
  const ivBytes = base64ToBytes(currentPacket.iv);

  if (currentPacket.mode === "CBC") {
    const key = await importKey(keyBytes, "AES-CBC");
    const ciphertext = base64ToBytes(currentPacket.ciphertext);
    const paddedPlaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-CBC", iv: ivBytes }, key, ciphertext)
    );
    els.decryptedOutput.textContent = bytesToText(pkcs7Unpad(paddedPlaintext));
  } else {
    const key = await importKey(keyBytes, "AES-GCM");
    const ciphertext = base64ToBytes(currentPacket.ciphertext);
    const tag = base64ToBytes(currentPacket.tag);
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);
    const aadBytes = currentPacket.aad ? base64ToBytes(currentPacket.aad) : new Uint8Array();
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes, additionalData: aadBytes, tagLength: 128 },
        key,
        combined
      )
    );
    els.decryptedOutput.textContent = bytesToText(plaintext);
  }

  renderNotes();
}

function explainModeChoice() {
  const engine = els.engineSelect.value;
  let message = "";

  if (engine === "CBC") {
    message = [
      "CBC explanation:",
      "- Good for showing block encryption with an IV.",
      "- Requires padding.",
      "- Does not provide integrity by itself.",
    ].join("\n");
  } else if (engine === "GCM") {
    message = [
      "GCM explanation:",
      "- Provides confidentiality and integrity.",
      "- Uses a nonce and authentication tag.",
      "- Good for explaining why tampering gets detected.",
    ].join("\n");
  } else {
    message = [
      "Rijndael trace explanation:",
      "- Use the trace viewer with exported trace.json.",
      "- Walk through AddRoundKey, SubBytes, ShiftRows, and MixColumns.",
      "- This mode is for explanation rather than browser-side encryption.",
    ].join("\n");
  }

  els.notesOutput.textContent = message;
}

function renderTrace(trace) {
  if (!Array.isArray(trace) || trace.length === 0) {
    els.traceOutput.innerHTML = '<p class="muted">No trace loaded.</p>';
    return;
  }

  els.traceOutput.innerHTML = trace
    .slice(0, 24)
    .map((entry) => `
      <article class="trace-card">
        <div class="trace-meta">Round ${entry.round} · ${entry.step}</div>
        <div><code>${entry.state_hex}</code></div>
      </article>
    `)
    .join("");
}

function renderNotes() {
  const mode = currentPacket?.mode || els.engineSelect.value;
  const noteLines = [
    `Presentation cue: explain why ${mode} was selected for this example.`,
    `Key size shown on screen: ${hexToBytes(els.keyInput.value).length * 8} bits.`,
  ];

  if (loadedTrace) {
    noteLines.push(`Loaded Rijndael trace entries: ${loadedTrace.length}.`);
  }

  els.notesOutput.textContent = noteLines.join("\n");
}

function renderOutputs() {
  els.packetOutput.textContent = JSON.stringify(currentPacket || {}, null, 2);
  renderNotes();
}

function loadPreset() {
  const preset = presets[els.presetSelect.value];
  els.engineSelect.value = preset.engine;
  els.keyInput.value = preset.keyHex;
  els.ivInput.value = preset.ivHex;
  els.aadInput.value = preset.aad;
  els.plaintextInput.value = preset.plaintext;
  els.decryptedOutput.textContent = "";
  currentPacket = null;
  loadedTrace = null;
  renderTrace([]);
  explainModeChoice();
}

async function loadTraceFile(file) {
  const text = await file.text();
  const parsed = JSON.parse(text);
  loadedTrace = Array.isArray(parsed) ? parsed : [];
  renderTrace(loadedTrace);
  els.engineSelect.value = "TRACE";
  currentPacket = { engine: "Rijndael Trace Viewer", traceEntries: loadedTrace.length };
  renderOutputs();
}

function bootstrapPresets() {
  Object.keys(presets).forEach((name) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    els.presetSelect.append(option);
  });
  els.presetSelect.value = "Standard CBC Walkthrough";
  loadPreset();
}

els.loadPresetButton.addEventListener("click", loadPreset);
els.encryptButton.addEventListener("click", async () => {
  try {
    await encryptCurrent();
    els.decryptedOutput.textContent = "";
  } catch (error) {
    els.decryptedOutput.textContent = `Error: ${error.message}`;
  }
});

els.decryptButton.addEventListener("click", async () => {
  try {
    await decryptCurrent();
  } catch (error) {
    els.decryptedOutput.textContent = `Error: ${error.message}`;
  }
});

els.patternButton.addEventListener("click", explainModeChoice);
els.traceFileInput.addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) {
    return;
  }
  try {
    await loadTraceFile(file);
  } catch (error) {
    els.traceOutput.innerHTML = `<p class="warning">Could not load trace: ${error.message}</p>`;
  }
});

bootstrapPresets();