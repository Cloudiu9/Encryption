const HASH_MARKER_START = "---HASH-START---";
const HASH_MARKER_END = "---HASH-END---";
let inMemoryPrivateKey = null; // CryptoKey
let inMemoryPublicJwk = null;

function autoResize(el) {
  el.style.height = "auto";
  el.style.height = el.scrollHeight + "px";
}

function log(msg) {
  const a = document.getElementById("logArea");
  const now = new Date().toLocaleTimeString();
  a.textContent = now + " - " + msg + "\n" + a.textContent;
}

// --- Converters ---
function strToUtf8(str) {
  return new TextEncoder().encode(str);
}
function utf8ToStr(buf) {
  return new TextDecoder().decode(buf);
}
function bufToHex(buffer) {
  let hex = "";
  const view = new Uint8Array(buffer);
  for (const b of view) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}
function hexToBuf(hex) {
  const len = hex.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out.buffer;
}
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function sha256(buf) {
  const res = await crypto.subtle.digest("SHA-256", buf);
  return res; // ArrayBuffer
}
async function sha256HexFromString(str) {
  const buf = strToUtf8(str);
  const hash = await sha256(buf);
  return bufToHex(hash);
}

// --- PBKDF2 KDF ---
async function deriveKeyPBKDF2(password, saltBase64, iterations = 100000) {
  const salt = base64ToArrayBuffer(saltBase64);
  const pwKey = await crypto.subtle.importKey(
    "raw",
    strToUtf8(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
    pwKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return key;
}

// --- LFSR KDF (educational) ---
async function deriveKeyLFSR(password) {
  // seed = SHA-256(password)
  const seedBuf = await sha256(strToUtf8(password));
  const seed = new Uint8Array(seedBuf); // 32 bytes = 256 bits register
  const reg = new Uint8Array(32);
  reg.set(seed);
  const out = new Uint8Array(32);
  for (let byte = 0; byte < 32; byte++) {
    let val = 0;
    for (let bit = 0; bit < 8; bit++) {
      // taps: bits at positions 0 and 2 (LSB = bit 0 of last byte)
      const bit0 = reg[31] & 1;
      const bit2 = (reg[31] >> 2) & 1;
      const fb = bit0 ^ bit2;
      // shift right by 1 across the 32-byte register
      let carry = fb;
      for (let i = 0; i < 32; i++) {
        const newCarry = reg[i] & 1;
        reg[i] = (reg[i] >> 1) | (carry << 7);
        carry = newCarry;
      }
      val = (val << 1) | (reg[31] & 1); // use LSB as output bit
    }
    out[byte] = val & 0xff;
  }
  // import as AES key
  return await crypto.subtle.importKey(
    "raw",
    out.buffer,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
}

// --- AES-CBC encrypt/decrypt ---
async function aesCbcEncrypt(plaintextBuf, cryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: iv },
    cryptoKey,
    plaintextBuf
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    ciphertext: arrayBufferToBase64(ct),
  };
}
async function aesCbcDecrypt(base64Ciphertext, ivBase64, cryptoKey) {
  const ctBuf = base64ToArrayBuffer(base64Ciphertext);
  const ivBuf = base64ToArrayBuffer(ivBase64);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: new Uint8Array(ivBuf) },
      cryptoKey,
      ctBuf
    );
    return pt; // ArrayBuffer
  } catch (e) {
    // Do not reveal password correctness; rethrow so caller can handle gracefully
    log("Decryption produced an error: " + e.message);
    throw e;
  }
}

// --- ECDSA keypair, sign, verify ---
async function generateEcdsaKeypair() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  inMemoryPrivateKey = kp.privateKey;
  inMemoryPublicJwk = pubJwk;
  document.getElementById("publicKeyArea").value = JSON.stringify(
    pubJwk,
    null,
    2
  );
  autoResize(publicKeyArea);
  document.getElementById("keyStatus").textContent = "Keypair generată (P-256)";
  log("Keypair generată");
}

async function importPrivateJwk(file) {
  const ab = await fileToArrayBuffer(file);
  const str = utf8ToStr(ab);
  const jwk = JSON.parse(str);
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  );
  inMemoryPrivateKey = key;
  if (jwk.x) {
    const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true };
    inMemoryPublicJwk = pub;
    document.getElementById("publicKeyArea").value = JSON.stringify(
      pub,
      null,
      2
    );
  }
  document.getElementById("keyStatus").textContent = "Cheie privată importată";
  log("Cheie privată importată");
}

async function signHex(hashHex) {
  if (!inMemoryPrivateKey) throw new Error("Private key not available");
  const data = hexToBuf(hashHex);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    inMemoryPrivateKey,
    data
  );
  return arrayBufferToBase64(sig);
}

async function verifySignatureWithJwk(pubJwk, signatureBase64, hashHex) {
  try {
    const pubKey = await crypto.subtle.importKey(
      "jwk",
      pubJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    const sigBuf = base64ToArrayBuffer(signatureBase64);
    const dataBuf = hexToBuf(hashHex);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pubKey,
      sigBuf,
      dataBuf
    );
    return ok;
  } catch (e) {
    log("Error verifying signature: " + e.message);
    return false;
  }
}

// --- File helpers ---
function fileToArrayBuffer(file) {
  return new Promise((res) => {
    const r = new FileReader();
    r.onload = (e) => res(e.target.result);
    r.readAsArrayBuffer(file);
  });
}
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
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// --- Main flows ---
async function onEncryptClick() {
  try {
    const fileIn = document.getElementById("encryptFileInput").files[0];
    if (!fileIn) return alert("Alege un fișier .txt");
    const text = await fileToText(fileIn);
    if (text.length < 500) {
      document.getElementById("encryptMsg").textContent =
        "Fișierul trebuie să aibă minim 500 caractere.";
      log("Fișier prea scurt");
      return;
    }
    const password = document.getElementById("encryptPassword").value || "";
    const kdf = document.getElementById("kdfSelect").value;
    let aesKey;
    let header = { version: 1, cipher: "AES-CBC", kdf: kdf, kdfParams: {} };

    if (kdf === "pbkdf2") {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltB64 = arrayBufferToBase64(salt.buffer);
      header.kdfParams.salt = saltB64;
      header.kdfParams.iterations = 100000;
      aesKey = await deriveKeyPBKDF2(
        password,
        saltB64,
        header.kdfParams.iterations
      );
    } else {
      // LFSR
      aesKey = await deriveKeyLFSR(password);
      header.kdfParams = { note: "lfsr-derived-from-password" };
    }

    // compute hash of file
    const hashHex = await sha256HexFromString(text);
    // build textWithHash
    const textWithHash = text + HASH_MARKER_START + hashHex + HASH_MARKER_END;
    // sign if requested
    let signature = null;
    let publicJwk = null;
    if (document.getElementById("signCheckbox").checked && inMemoryPrivateKey) {
      signature = await signHex(hashHex);
      publicJwk = inMemoryPublicJwk;
    }
    const inner = {
      textWithHash: textWithHash,
      signature: signature,
      publicKeyJwk: publicJwk,
    };
    const innerStr = JSON.stringify(inner);
    const innerBuf = strToUtf8(innerStr);
    const encResult = await aesCbcEncrypt(innerBuf, aesKey);
    header.iv = encResult.iv;
    header.payload = encResult.ciphertext;
    const outStr = JSON.stringify(header, null, 2);
    downloadBlob(fileIn.name + ".enc", outStr, "application/json");
    document.getElementById("encryptMsg").textContent =
      "Fișier criptat: descărcat.";
    log("Fișier criptat și salvat");
  } catch (e) {
    log("Encrypt error: " + e.message);
    document.getElementById("encryptMsg").textContent = "Eroare la criptare.";
  }
}

async function onDecryptClick() {
  try {
    const fileIn = document.getElementById("decryptFileInput").files[0];
    if (!fileIn) return alert("Alege un fișier .enc");
    const txt = await fileToText(fileIn);
    const header = JSON.parse(txt);
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
    // decrypt
    let innerBuf;
    try {
      innerBuf = await aesCbcDecrypt(header.payload, header.iv, aesKey);
    } catch (e) {
      // decryption error - avoid revealing password correctness
      document.getElementById("verificationResults").textContent =
        "Decriptare eșuată sau conținut corupt.";
      log("Decryption failed with error: " + e.message);
      return;
    }
    const innerStr = utf8ToStr(innerBuf);
    const inner = JSON.parse(innerStr);
    const txtWithHash = inner.textWithHash || "";
    // split text and hash
    const startIdx = txtWithHash.indexOf(HASH_MARKER_START);
    const endIdx = txtWithHash.indexOf(HASH_MARKER_END);
    let originalText = txtWithHash;
    let embeddedHash = null;
    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
      originalText = txtWithHash.substring(0, startIdx);
      embeddedHash = txtWithHash.substring(
        startIdx + HASH_MARKER_START.length,
        endIdx
      );
    }
    const recomputedHash = await sha256HexFromString(originalText);
    const hashOk = embeddedHash && recomputedHash === embeddedHash;
    let sigResult = "Semnătură absentă";
    if (inner.signature && inner.publicKeyJwk) {
      const ok = await verifySignatureWithJwk(
        inner.publicKeyJwk,
        inner.signature,
        embeddedHash || recomputedHash
      );
      sigResult = ok ? "Semnătură validă" : "Semnătură invalidă";
    }
    // display results
    document.getElementById("decryptedOutput").value = originalText;
    autoResize(document.getElementById("decryptedOutput"));
    document.getElementById("verificationResults").textContent =
      (hashOk ? "HASHUL este corect." : "HASHUL este incorect.") +
      " | " +
      sigResult;
    log("Decriptare finalizată. HASH ok: " + hashOk);
  } catch (e) {
    log("Decrypt error: " + e.message);
    if (!document.getElementById("verificationResults").textContent)
      document.getElementById("verificationResults").textContent =
        "Eroare la decriptare.";
  }
}

// --- Wire UI ---
window.addEventListener("load", () => {
  document.getElementById("btnGenerateKey").onclick = generateEcdsaKeypair;
  document.getElementById("btnImportKey").onclick = () =>
    document.getElementById("importKeyFile").click();
  document.getElementById("importKeyFile").onchange = async (e) => {
    const f = e.target.files[0];
    if (f) await importPrivateJwk(f);
  };
  document.getElementById("btnEncrypt").onclick = onEncryptClick;
  document.getElementById("btnDecrypt").onclick = onDecryptClick;
  document.getElementById("btnExportPub").onclick = () => {
    if (inMemoryPublicJwk)
      downloadBlob("publicKey.jwk", JSON.stringify(inMemoryPublicJwk, null, 2));
    else alert("Nicio cheie publică");
  };
});
