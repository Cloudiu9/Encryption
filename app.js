// ================= CONSTANTE =================
const HASH_MARKER_START = "---HASH-START---";
const HASH_MARKER_END = "---HASH-END---";

// ================= UTILITARE UI =================
function autoResize(el) {
  el.style.height = "auto";
  el.style.height = el.scrollHeight + "px";
}

function log(msg) {
  const area = document.getElementById("logArea");
  const now = new Date().toLocaleTimeString();
  area.textContent = now + " - " + msg + "\n" + area.textContent;
}

// ================= CONVERSII =================
function strToUtf8(str) {
  return new TextEncoder().encode(str);
}

function utf8ToStr(buf) {
  return new TextDecoder().decode(buf);
}

function bufToHex(buffer) {
  const view = new Uint8Array(buffer);
  let hex = "";
  for (const b of view) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function hexToBuf(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out.buffer;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out.buffer;
}

// ================= HASH SHA-256 =================
async function sha256(buf) {
  return await crypto.subtle.digest("SHA-256", buf);
}

async function sha256HexFromString(str) {
  const buf = strToUtf8(str);
  const hash = await sha256(buf);
  return bufToHex(hash);
}

// ================= KDF PBKDF2 =================
async function deriveKeyPBKDF2(password, saltBase64, iterations = 100000) {
  const salt = base64ToArrayBuffer(saltBase64);
  const pwKey = await crypto.subtle.importKey(
    "raw",
    strToUtf8(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    pwKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ================= KDF LFSR =================
async function deriveKeyLFSR(password) {
  const seedBuf = await sha256(strToUtf8(password));
  const reg = new Uint8Array(seedBuf);
  const out = new Uint8Array(32);

  for (let byte = 0; byte < 32; byte++) {
    let val = 0;
    for (let bit = 0; bit < 8; bit++) {
      const bit0 = reg[31] & 1;
      const bit2 = (reg[31] >> 2) & 1;
      const fb = bit0 ^ bit2;

      let carry = fb;
      for (let i = 0; i < 32; i++) {
        const newCarry = reg[i] & 1;
        reg[i] = (reg[i] >> 1) | (carry << 7);
        carry = newCarry;
      }
      val = (val << 1) | (reg[31] & 1);
    }
    out[byte] = val;
  }

  return await crypto.subtle.importKey(
    "raw",
    out.buffer,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
}

// ================= AES-CBC =================
async function aesCbcEncrypt(plaintextBuf, key) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    plaintextBuf
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    ciphertext: arrayBufferToBase64(ct),
  };
}

async function aesCbcDecrypt(ciphertextB64, ivB64, key) {
  const ctBuf = base64ToArrayBuffer(ciphertextB64);
  const ivBuf = base64ToArrayBuffer(ivB64);
  return await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: new Uint8Array(ivBuf) },
    key,
    ctBuf
  );
}

// ================= FILE HELPERS =================
function fileToText(file) {
  return new Promise((res) => {
    const r = new FileReader();
    r.onload = (e) => res(e.target.result);
    r.readAsText(file);
  });
}

function downloadBlob(filename, content, mime = "application/json") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ================= CRIPTARE =================
async function onEncryptClick() {
  try {
    const file = document.getElementById("encryptFileInput").files[0];
    if (!file) return alert("Selectează un fișier .txt");

    const text = await fileToText(file);
    if (text.length < 500) {
      log("Fișier prea scurt");
      return;
    }

    const password = document.getElementById("encryptPassword").value || "";
    const kdf = document.getElementById("kdfSelect").value;
    let aesKey;
    const header = { cipher: "AES-CBC", kdf, kdfParams: {} };

    if (kdf === "pbkdf2") {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      header.kdfParams.salt = arrayBufferToBase64(salt.buffer);
      header.kdfParams.iterations = 100000;
      aesKey = await deriveKeyPBKDF2(
        password,
        header.kdfParams.salt,
        header.kdfParams.iterations
      );
    } else {
      aesKey = await deriveKeyLFSR(password);
      header.kdfParams.note = "lfsr";
    }

    const hashHex = await sha256HexFromString(text);

    // Download hash
    downloadBlob("hash.txt", hashHex, "text/plain");

    const textWithHash = text + HASH_MARKER_START + hashHex + HASH_MARKER_END;

    const enc = await aesCbcEncrypt(strToUtf8(textWithHash), aesKey);
    header.iv = enc.iv;
    header.payload = enc.ciphertext;

    downloadBlob(file.name + ".enc", JSON.stringify(header, null, 2));
    log("Fișier criptat");
  } catch (e) {
    log("Eroare criptare: " + e.message);
  }
}

// ================= DECRIPTARE =================
async function onDecryptClick() {
  try {
    const file = document.getElementById("decryptFileInput").files[0];
    if (!file) return alert("Selectează un fișier .enc");

    const header = JSON.parse(await fileToText(file));
    const password = document.getElementById("decryptPassword").value || "";
    let aesKey;

    if (header.kdf === "pbkdf2") {
      aesKey = await deriveKeyPBKDF2(
        password,
        header.kdfParams.salt,
        header.kdfParams.iterations
      );
    } else {
      aesKey = await deriveKeyLFSR(password);
    }

    let plaintext;
    let decryptionFailed = false;

    try {
      plaintext = await aesCbcDecrypt(header.payload, header.iv, aesKey);
    } catch {
      decryptionFailed = true;

      // folosim ciphertext-ul ca "text decriptat ilizibil"
      plaintext = base64ToArrayBuffer(header.payload);

      // log("Decriptare realizata.");
    }

    let displayedText = "";
    let hashOk = false;

    if (decryptionFailed) {
      // afisam direct datele ilizibile
      displayedText = utf8ToStr(plaintext);
      hashOk = false;
    } else {
      const txt = utf8ToStr(plaintext);

      const start = txt.indexOf(HASH_MARKER_START);
      const end = txt.indexOf(HASH_MARKER_END);

      let originalText = txt;
      let embeddedHash = "";

      if (start !== -1 && end !== -1 && end > start) {
        originalText = txt.substring(0, start);
        embeddedHash = txt.substring(start + HASH_MARKER_START.length, end);
      }

      const recomputed = await sha256HexFromString(originalText);
      hashOk = embeddedHash === recomputed;
      displayedText = originalText;
    }

    document.getElementById("decryptedOutput").value = displayedText;
    autoResize(document.getElementById("decryptedOutput"));

    document.getElementById("verificationResults").textContent = hashOk
      ? "HASHUL este corect."
      : "HASHUL este incorect.";

    log("Decriptare finalizată.");
    // log("Decriptare finalizată. HASH ok: " + hashOk);
  } catch (e) {
    log("Eroare decriptare: " + e.message);
  }
}

// ================= WIRE UI =================
window.addEventListener("load", () => {
  document.getElementById("btnEncrypt").onclick = onEncryptClick;
  document.getElementById("btnDecrypt").onclick = onDecryptClick;
});
