const win = typeof window !== "undefined" ? window : globalThis;
const DEFAULT_OPTIONS = {
  rpcUrl: "https://pubnodes.cypherium.io/rpc",
  pbkdf2Iterations: 600000,
  autoLockMs: 5 * 60 * 1000
};

const runtimeOptions = Object.assign(
  {},
  DEFAULT_OPTIONS,
  win.SECRET_WALLET_OPTIONS || {}
);

if (typeof win.SECRET_WALLET_RPC_URL === "string" && win.SECRET_WALLET_RPC_URL.trim()) {
  runtimeOptions.rpcUrl = win.SECRET_WALLET_RPC_URL.trim();
}

if (typeof win.SECRET_WALLET_PBKDF2 === "number" && win.SECRET_WALLET_PBKDF2 > 0) {
  runtimeOptions.pbkdf2Iterations = Math.floor(win.SECRET_WALLET_PBKDF2);
}

if (typeof win.SECRET_WALLET_AUTOLOCK_MS === "number" && win.SECRET_WALLET_AUTOLOCK_MS > 0) {
  runtimeOptions.autoLockMs = Math.floor(win.SECRET_WALLET_AUTOLOCK_MS);
}

const provider = new ethers.providers.JsonRpcProvider(runtimeOptions.rpcUrl);

let current = {
  privKeyHex: null,
  wallet: null,
  chainId: null,
};

let autoLockTimer = null;

function clearAutoLockTimer() {
  if (autoLockTimer) {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
  }
}

function scheduleAutoLock() {
  clearAutoLockTimer();
  const timeout = resolveAutoLockMs();
  if (!timeout || timeout <= 0) {
    return;
  }
  autoLockTimer = setTimeout(() => {
    forgetAll("Forgot (Timed Out)");
  }, timeout);
}

function resolveIterations() {
  if (typeof runtimeOptions.pbkdf2Iterations === "number" && runtimeOptions.pbkdf2Iterations > 0) {
    return runtimeOptions.pbkdf2Iterations;
  }
  if (typeof navigator !== "undefined") {
    const cores = navigator.hardwareConcurrency || 4;
    if (cores <= 2) {
      return 200000;
    }
    if (cores <= 4) {
      return 450000;
    }
  }
  return DEFAULT_OPTIONS.pbkdf2Iterations;
}

function resolveAutoLockMs() {
  if (typeof runtimeOptions.autoLockMs === "number" && runtimeOptions.autoLockMs > 0) {
    return runtimeOptions.autoLockMs;
  }
  return DEFAULT_OPTIONS.autoLockMs;
}

// ===== KDF: PBKDF2-HMAC-SHA-256 (WebCrypto) =====
function getSubtleCrypto() {
  const { crypto } = globalThis;
  if (!crypto) {
    return null;
  }

  if (crypto.subtle) {
    return crypto.subtle;
  }

  if (crypto.webcrypto && crypto.webcrypto.subtle) {
    return crypto.webcrypto.subtle;
  }

  return null;
}

function getPBKDF2() {
  if (ethers && typeof ethers.pbkdf2 === "function") {
    return ethers.pbkdf2.bind(ethers);
  }
  if (ethers && ethers.utils && typeof ethers.utils.pbkdf2 === "function") {
    return ethers.utils.pbkdf2.bind(ethers.utils);
  }
  return null;
}

function toBytes(value) {
  if (ethers && typeof ethers.getBytes === "function") {
    return ethers.getBytes(value);
  }
  if (ethers && ethers.utils && typeof ethers.utils.arrayify === "function") {
    return ethers.utils.arrayify(value);
  }
  throw new Error("Byte conversion unavailable in this environment");
}

function toUtf8Bytes(value) {
  if (ethers && typeof ethers.toUtf8Bytes === "function") {
    return ethers.toUtf8Bytes(value);
  }
  if (ethers && ethers.utils && typeof ethers.utils.toUtf8Bytes === "function") {
    return ethers.utils.toUtf8Bytes(value);
  }
  return new TextEncoder().encode(value);
}

async function kdfPBKDF2(passphrase, salt, iterations) {
  const subtle = getSubtleCrypto();

  if (subtle) {
    const enc = new TextEncoder();
    const keyMaterial = await subtle.importKey(
      "raw",
      enc.encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations },
      keyMaterial,
      256
    );
    return new Uint8Array(bits);
  }

  const pbkdf2 = getPBKDF2();
  if (!pbkdf2) {
    throw new Error(
      "PBKDF2 is unavailable in this context. Use HTTPS or upgrade the ethers build."
    );
  }

  const passphraseBytes = toUtf8Bytes(passphrase);
  const saltBytes = toUtf8Bytes(salt);
  const derived = await pbkdf2(
    passphraseBytes,
    saltBytes,
    iterations,
    32,
    "sha256"
  );
  return toBytes(derived);
}

function clampToSecp256k1(bytes32) {
  const allZero = bytes32.every(b => b === 0);
  if (allZero) throw new Error("Derived key is zero; choose a stronger passphrase/salt.");
  return bytes32;
}

function toHex(bytes) {
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function deriveAndLoad(passphrase, salt) {
  const keyBytes = await kdfPBKDF2(passphrase, salt, resolveIterations());
  const clamped = clampToSecp256k1(keyBytes);
  const privKeyHex = toHex(clamped);
  const wallet = new ethers.Wallet(privKeyHex, provider);
  const net = await provider.getNetwork();
  current.privKeyHex = privKeyHex;
  current.wallet = wallet;
  current.chainId = net.chainId;
  scheduleAutoLock();
  return { address: await wallet.getAddress(), chainId: net.chainId };
}

function forgetAll(message) {
  current.privKeyHex = null;
  current.wallet = null;
  current.chainId = null;
  clearAutoLockTimer();
  document.getElementById("passphrase").value = "";
  document.getElementById("salt").value = "";
  document.getElementById("whoami").textContent = message || "Forgot (Cleared Memory)";
}

// ===== UI Handlers =====
document.getElementById("derive").addEventListener("click", async () => {
  const passphrase = document.getElementById("passphrase").value;
  const salt = document.getElementById("salt").value;
  const whoami = document.getElementById("whoami");
  try {
    const { address, chainId } = await deriveAndLoad(passphrase, salt);
    whoami.textContent = `Address:\n${address}\nChainId:\n${chainId}`;
  } catch (e) {
    whoami.textContent = `error: ${e.message}`;
  }
});

document.getElementById("forget").addEventListener("click", () => forgetAll());

document.getElementById("refresh").addEventListener("click", async () => {
  const out = document.getElementById("balance");
  try {
    if (!current.wallet) {
      throw new Error("Derive a wallet first");
    }
    scheduleAutoLock();
    const balWei = await provider.getBalance(current.wallet.address);
    const bal = ethers.formatUnits(balWei, 18);
    out.textContent = `Balance: ${bal} CPH`;
  } catch (e) {
    out.textContent = `error: ${e.message}`;
  }
});

document.getElementById("send").addEventListener("click", async () => {
  const to = document.getElementById("to").value.trim();
  const amount = document.getElementById("amount").value.trim();
  const out = document.getElementById("txout");
  try {
    if (!current.wallet) {
      throw new Error("Derive a wallet first");
    }
    scheduleAutoLock();
    const nonce = await provider.getTransactionCount(current.wallet.address);
    const gasPrice = await provider.getGasPrice();
    const value = ethers.parseUnits(amount, 18);
    const gasLimit = ethers.BigNumber.from("21000");
    const tx = { to, value, gasLimit, gasPrice, nonce, chainId: current.chainId };
    const sent = await current.wallet.sendTransaction(tx);
    out.textContent = `sending... TxHash: ${sent.hash}`;
  } catch (e) {
    out.textContent = `error: ${e.message}`;
  }
});

win.addEventListener("beforeunload", () => {
  forgetAll();
});

win.addEventListener("pagehide", () => {
  forgetAll();
});
