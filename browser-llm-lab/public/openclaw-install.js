// Official stable desktop assets verified on 2026-10-02 against https://openclaw.ai/
// and the GitHub Releases API (each tag was neither a draft nor a prerelease):
// https://api.github.com/repos/openclaw/openclaw/releases/tags/v2026.9.7
// https://api.github.com/repos/openclaw/openclaw-windows-node/releases/tags/v2026.9.4
// https://api.github.com/repos/openclaw/openclaw/releases/tags/v2026.9.5
// Desktop platforms publish separately; do not substitute the latest Gateway version.
const MAIN_RELEASES = "https://github.com/openclaw/openclaw/releases/download";
const WINDOWS_RELEASES = "https://github.com/openclaw/openclaw-windows-node/releases/download";
export const OPENCLAW_VERIFIED_AT = "2026-10-02";
export const OPENCLAW_COMPANION_VERIFIED_AT = "2026-10-03";

const PLATFORMS = {
  macos: {
    docsUrl: "https://docs.openclaw.ai/platforms/macos",
    requirements: "macOS 15 or later. This page cannot verify your OS version.",
  },
  windows: {
    docsUrl: "https://docs.openclaw.ai/platforms/windows",
    requirements: "Windows 10 20H2 or later / Windows 11. This page cannot verify your OS version.",
  },
  linux: {
    docsUrl: "https://docs.openclaw.ai/platforms/linux",
    requirements: "x64 only. AppImage requires glibc 2.35 or later and GLIBCXX_3.4.30. Check distribution compatibility in the official instructions.",
  },
};

// Store destinations verified through the official platform documentation on 2026-10-03:
// https://docs.openclaw.ai/platforms/ios
// https://docs.openclaw.ai/platforms/android
// Both apps are companion nodes; neither hosts the Gateway on the mobile device.
const COMPANIONS = Object.freeze({
  ios: Object.freeze({
    companionUrl: "https://apps.apple.com/app/openclaw-ai-that-does-things/id6780396132",
    companionLabel: "Get OpenClaw for iPhone / iPad",
    docsUrl: "https://docs.openclaw.ai/platforms/ios",
    requirements: "iOS / iPadOS 18 or later. A running OpenClaw Gateway on another computer must be reachable from this device.",
    reason: "The iOS companion connects to your Gateway for chat and device features. It does not host the Gateway on this phone or tablet.",
  }),
  android: Object.freeze({
    companionUrl: "https://play.google.com/store/apps/details?id=ai.openclaw.app",
    companionLabel: "Get OpenClaw for Android",
    docsUrl: "https://docs.openclaw.ai/platforms/android",
    requirements: "Check device compatibility in Google Play. A running OpenClaw Gateway on another computer must be reachable from this device.",
    reason: "The Android companion connects to your Gateway for chat and device features. It does not host the Gateway on this phone or tablet.",
  }),
});
const ALLOWED_COMPANIONS = new Set(Object.values(COMPANIONS).map(item => item.companionUrl));

function artifact(platform, packageArchitecture, version, fileName, label, format) {
  const origin = platform === "windows" ? WINDOWS_RELEASES : MAIN_RELEASES;
  return Object.freeze({ platform, packageArchitecture, version, fileName, label, format,
    downloadUrl: `${origin}/v${version}/${fileName}`, ...PLATFORMS[platform] });
}

const MAC = Object.freeze({
  unknown: artifact("macos", "universal", "2026.9.7", "OpenClaw-2026.9.7.dmg", "macOS / Universal", "dmg"),
  arm64: artifact("macos", "arm64", "2026.9.7", "OpenClaw-2026.9.7-arm64.dmg", "macOS / Apple Silicon", "dmg"),
  x64: artifact("macos", "x64", "2026.9.7", "OpenClaw-2026.9.7-x86_64.dmg", "macOS / Intel", "dmg"),
});
const WINDOWS = Object.freeze({
  x64: artifact("windows", "x64", "2026.9.4", "OpenClawCompanion-Setup-x64.exe", "Windows / x64", "exe"),
  arm64: artifact("windows", "arm64", "2026.9.4", "OpenClawCompanion-Setup-arm64.exe", "Windows / ARM64", "exe"),
});
const LINUX = Object.freeze({
  appimage: artifact("linux", "x64", "2026.9.5", "OpenClaw-2026.9.5-amd64.AppImage", "Linux / x64 AppImage", "appimage"),
  deb: artifact("linux", "x64", "2026.9.5", "OpenClaw-2026.9.5-amd64.deb", "Linux / x64 Debian package", "deb"),
});
const ALLOWED_DOWNLOADS = new Set([...Object.values(MAC), ...Object.values(WINDOWS),
  ...Object.values(LINUX)].map(item => item.downloadUrl));

/** Only the exact, verified official assets can become download links. */
export function isOfficialOpenClawDownload(url) {
  return typeof url === "string" && ALLOWED_DOWNLOADS.has(url);
}

/** Store links are deliberately separate from native desktop download links. */
export function isOfficialOpenClawCompanion(url) {
  return typeof url === "string" && ALLOWED_COMPANIONS.has(url);
}

function mobilePlatformName(value) {
  const text = String(value || "").toLowerCase();
  if (["ios", "ipados", "iphone", "ipad", "ipod"].includes(text)) return "ios";
  if (text === "android") return "android";
  return "unknown";
}

function platformName(value) {
  const text = String(value || "").toLowerCase();
  if (/^(macos|mac os|mac os x|macintel|darwin)$/.test(text)) return "macos";
  if (/^(windows|win32|win64)$/.test(text)) return "windows";
  if (/^linux(?:\s|$)/.test(text)) return "linux";
  return "unknown";
}

function architectureName(value, bitness) {
  const text = String(value || "").toLowerCase();
  if (String(bitness) === "32") return "unknown";
  if (["arm64", "aarch64"].includes(text)) return "arm64";
  if (["x64", "x86_64", "amd64"].includes(text)) return "x64";
  if (String(bitness) === "64" && text === "arm") return "arm64";
  if (String(bitness) === "64" && text === "x86") return "x64";
  return "unknown";
}

/**
 * Read only browser-provided device hints. No requests, local probes or downloads.
 * UA strings / MacIntel can hide CPU architecture, so they only identify the OS.
 * https://learn.microsoft.com/en-us/microsoft-edge/web-platform/how-to-detect-win11
 */
export async function detectClientPlatform(navigatorLike = globalThis.navigator || {}) {
  const ua = String(navigatorLike.userAgent || "");
  const legacyPlatform = String(navigatorLike.platform || "");
  const uaData = navigatorLike.userAgentData;
  let hints = null;
  if (typeof uaData?.getHighEntropyValues === "function") {
    try { hints = await uaData.getHighEntropyValues(["architecture", "bitness"]); }
    catch { /* The browser may withhold high-entropy values. Manual choices still work. */ }
  }
  let mobilePlatform = mobilePlatformName(hints?.platform || uaData?.platform || legacyPlatform);
  if (mobilePlatform === "unknown" && !/Windows Phone/i.test(ua)) {
    if (/Android/i.test(ua)) mobilePlatform = "android";
    else if (/iPhone|iPad|iPod/i.test(ua) ||
      (/Mac/i.test(legacyPlatform || ua) && navigatorLike.maxTouchPoints > 1)) mobilePlatform = "ios";
  }
  const mobile = Boolean(mobilePlatform !== "unknown" || uaData?.mobile || hints?.mobile ||
    /Android|iPhone|iPad|iPod|Windows Phone|\bMobile\b/i.test(ua) ||
    (/Mac/i.test(legacyPlatform) && navigatorLike.maxTouchPoints > 1));
  let platform = platformName(hints?.platform || uaData?.platform || legacyPlatform);
  // Android and iPad desktop UAs must never receive Linux or macOS desktop installers.
  if (mobile) platform = "unknown";
  else if (platform === "unknown" && !/CrOS/i.test(ua)) {
    if (/Windows NT/i.test(ua)) platform = "windows";
    else if (/Macintosh|Mac OS X/i.test(ua)) platform = "macos";
    else if (/Linux/i.test(ua)) platform = "linux";
  }
  // ChromeOS can expose Linux via navigator.platform without being a supported Linux desktop.
  if (/CrOS/i.test(ua) || /chrome\s?os/i.test(String(uaData?.platform || ""))) platform = "unknown";
  const bitness = ["32", "64"].includes(String(hints?.bitness)) ? String(hints.bitness) : "unknown";
  const architecture = mobile ? "unknown" : architectureName(hints?.architecture, bitness);
  return { platform, architecture, mobile, mobilePlatform, bitness,
    detectedBy: architecture !== "unknown" ? "client-hints"
      : platform !== "unknown" || mobilePlatform !== "unknown" ? "platform" : "unknown" };
}

/**
 * Return a download recommendation, never start a transfer or execute an installer.
 * Explicit UI selections can replace platform/architecture before calling this function.
 * GPU and RAM do not select an OpenClaw desktop package; this is separate from model choice.
 * `supported` only denotes a desktop download. A mobile companion has its own URL and
 * status, and `requiresGateway: true` means it needs a Gateway on another machine.
 */
export function recommendOpenClaw({ platform: inputPlatform, architecture: inputArchitecture,
  mobile = false, mobilePlatform: inputMobilePlatform, bitness, format = "appimage" } = {}) {
  const namedMobilePlatform = mobilePlatformName(inputMobilePlatform);
  const mobilePlatform = namedMobilePlatform !== "unknown" ? namedMobilePlatform : mobilePlatformName(inputPlatform);
  const isMobile = Boolean(mobile || mobilePlatform !== "unknown");
  const platform = isMobile ? "unknown" : platformName(inputPlatform);
  const architecture = isMobile ? "unknown" : architectureName(inputArchitecture, bitness);
  const base = { supported: false, platform, architecture, mobile: isMobile, mobilePlatform,
    status: "unsupported", downloadUrl: null, version: null, label: "OpenClaw",
    companionUrl: null, companionLabel: null, requiresGateway: isMobile,
    packageArchitecture: null, fileName: null, format: null, alternatives: [],
    docsUrl: "https://docs.openclaw.ai/install", requirements: "", verifiedAt: OPENCLAW_VERIFIED_AT,
    ...PLATFORMS[platform] };
  if (isMobile) {
    if (mobilePlatform !== "unknown") return { ...base, ...COMPANIONS[mobilePlatform],
      status: "companion", verifiedAt: OPENCLAW_COMPANION_VERIFIED_AT };
    return { ...base, status: "choose-mobile-platform",
      requirements: "Mobile companions need a running OpenClaw Gateway on another computer.",
      reason: "This appears to be a mobile device, but its OS could not be identified. Choose iOS or Android to find the official companion app." };
  }
  if (platform === "unknown") return { ...base, status: "choose-platform",
    reason: "Your OS could not be identified. Choose the OS and CPU of the computer you want to use." };
  if (String(bitness) === "32" || /^(ia32|i[3-6]86|armv7l?)$/i.test(String(inputArchitecture))) return { ...base,
    reason: "The verified official desktop packages do not include a 32-bit build. Check the official system requirements." };

  let selected, alternatives = [], reason;
  if (platform === "macos") {
    selected = MAC[architecture];
    reason = architecture === "unknown"
      ? "Your CPU could not be identified. The Universal app supports both Apple Silicon and Intel Macs."
      : "The official macOS app matches the selected OS and CPU.";
    alternatives = Object.values(MAC).filter(item => item !== selected);
  } else if (platform === "windows") {
    if (architecture === "unknown") return { ...base, status: "choose-architecture",
      alternatives: Object.values(WINDOWS),
      reason: "Your CPU could not be identified. Check x64 / ARM64 in your PC's system information and choose it here." };
    selected = WINDOWS[architecture];
    reason = "The official Windows Hub installer matches the selected OS and CPU.";
  } else {
    if (architecture === "unknown") return { ...base, status: "choose-architecture",
      reason: "Your CPU could not be identified. The verified Linux app is for x64. Check your CPU before selecting it." };
    if (architecture !== "x64") return { ...base,
      reason: "The verified official Linux desktop packages are for x64. For ARM64, see the official CLI installation instructions." };
    selected = LINUX[format === "deb" ? "deb" : "appimage"];
    alternatives = Object.values(LINUX).filter(item => item !== selected);
    reason = "The official Linux app is for x64. Check the required system libraries before installing.";
  }
  return { ...base, ...selected, supported: true, status: "ready", reason, alternatives };
}
