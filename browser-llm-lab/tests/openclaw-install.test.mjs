import test from "node:test";
import assert from "node:assert/strict";
import { detectClientPlatform, recommendOpenClaw, isOfficialOpenClawDownload,
  isOfficialOpenClawCompanion } from "../public/openclaw-install.js";

test("client hints match 64-bit Windows and macOS CPU packages", async () => {
  for (const [platform, architecture, expectedPlatform, expectedArchitecture] of [
    ["Windows", "arm", "windows", "arm64"], ["Windows", "x86", "windows", "x64"],
    ["macOS", "arm", "macos", "arm64"], ["Linux", "x86", "linux", "x64"],
  ]) {
    const device = await detectClientPlatform({ userAgentData: { platform, mobile: false,
      async getHighEntropyValues(keys) {
        assert.deepEqual(keys, ["architecture", "bitness"]);
        return { platform, architecture, bitness: "64" };
      } } });
    assert.equal(device.platform, expectedPlatform);
    assert.equal(device.architecture, expectedArchitecture);
    assert.equal(device.detectedBy, "client-hints");
    assert.equal(recommendOpenClaw(device).supported, true);
  }
});

test("legacy desktop user agents do not imply a CPU architecture", async () => {
  for (const [platform, userAgent, expected] of [
    ["MacIntel", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"],
    ["Win32", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"],
    ["Linux x86_64", "Mozilla/5.0 (X11; Linux x86_64)", "linux"],
  ]) {
    const device = await detectClientPlatform({ platform, userAgent });
    assert.equal(device.platform, expected);
    assert.equal(device.architecture, "unknown");
  }
  const mac = recommendOpenClaw(await detectClientPlatform({ platform: "MacIntel" }));
  assert.equal(mac.packageArchitecture, "universal");
  assert.match(mac.downloadUrl, /\/OpenClaw-2026\.9\.7\.dmg$/);
});

test("withheld, absent, or failing client hints remain usable without guessing", async () => {
  for (const getHighEntropyValues of [async () => ({ architecture: "x86" }), async () => ({}),
    async () => { throw new Error("Permission withheld"); }]) {
    const device = await detectClientPlatform({ userAgentData: { platform: "Windows", getHighEntropyValues } });
    assert.equal(device.platform, "windows");
    assert.equal(device.architecture, "unknown");
    const recommendation = recommendOpenClaw(device);
    assert.equal(recommendation.downloadUrl, null);
    assert.equal(recommendation.status, "choose-architecture");
    assert.deepEqual(recommendation.alternatives.map(item => item.packageArchitecture), ["x64", "arm64"]);
  }
  assert.equal((await detectClientPlatform({})).platform, "unknown");
  assert.equal(recommendOpenClaw({}).status, "choose-platform");
});

test("mobile and ChromeOS devices are never assigned a desktop installer", async () => {
  for (const navigatorLike of [
    { userAgent: "Mozilla/5.0 (Linux; Android 15; Tablet)", platform: "Linux aarch64" },
    { userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)" },
    { userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", platform: "MacIntel", maxTouchPoints: 5 },
    { userAgentData: { platform: "Android", mobile: true } },
    { userAgentData: { platform: "Android", mobile: false } },
    { userAgent: "Mozilla/5.0 (X11; CrOS x86_64 16093)", platform: "Linux x86_64" },
  ]) {
    const device = await detectClientPlatform(navigatorLike);
    assert.equal(device.platform, "unknown");
    assert.equal(recommendOpenClaw(device).downloadUrl, null);
  }
  assert.equal(recommendOpenClaw({ platform: "macos", architecture: "arm64", mobile: true }).supported, false);
  assert.equal((await detectClientPlatform({ userAgentData: { platform: "Android", mobile: false } })).mobile, true);
});

test("iOS and Android detection offers the matching official companion with a separate Gateway", async () => {
  for (const [navigatorLike, expected] of [
    [{ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)" }, "ios"],
    [{ userAgent: "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)" }, "ios"],
    [{ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", platform: "MacIntel", maxTouchPoints: 5 }, "ios"],
    [{ userAgent: "Mozilla/5.0 (Linux; Android 15; Tablet)", platform: "Linux aarch64" }, "android"],
    [{ userAgentData: { platform: "Android", mobile: false } }, "android"],
    [{ userAgentData: { platform: "iOS", mobile: true } }, "ios"],
  ]) {
    const device = await detectClientPlatform(navigatorLike);
    assert.equal(device.mobile, true);
    assert.equal(device.mobilePlatform, expected);
    assert.equal(device.architecture, "unknown");
    const recommendation = recommendOpenClaw(device);
    assert.equal(recommendation.status, "companion");
    assert.equal(recommendation.supported, false);
    assert.equal(recommendation.downloadUrl, null);
    assert.equal(recommendation.requiresGateway, true);
    assert.equal(recommendation.mobilePlatform, expected);
    assert.match(recommendation.docsUrl, new RegExp(`/platforms/${expected}$`));
    assert.match(recommendation.requirements, /Gateway on another computer/);
    assert.match(recommendation.reason, /does not host the Gateway/);
    assert.equal(isOfficialOpenClawCompanion(recommendation.companionUrl), true);
    assert.equal(isOfficialOpenClawDownload(recommendation.companionUrl), false);
  }
  assert.equal(recommendOpenClaw({ platform: "ios" }).companionUrl,
    "https://apps.apple.com/app/openclaw-ai-that-does-things/id6780396132");
  assert.equal(recommendOpenClaw({ platform: "android" }).companionUrl,
    "https://play.google.com/store/apps/details?id=ai.openclaw.app");
});

test("unknown mobile devices need an explicit platform choice instead of a guessed store", async () => {
  const device = await detectClientPlatform({ userAgent: "Mobile browser" });
  assert.equal(device.mobilePlatform, "unknown");
  const recommendation = recommendOpenClaw(device);
  assert.equal(recommendation.status, "choose-mobile-platform");
  assert.equal(recommendation.companionUrl, null);
  assert.equal(recommendation.downloadUrl, null);
  assert.equal(recommendation.requiresGateway, true);
  assert.equal(recommendOpenClaw({ ...device, mobilePlatform: "android" }).status, "companion");
  const phone = await detectClientPlatform({ userAgent: "Windows Phone 10.0; Android 6.0; Mobile" });
  assert.equal(phone.mobilePlatform, "unknown");
  assert.equal(recommendOpenClaw(phone).companionUrl, null);
});

test("store allowlist remains separate and rejects lookalikes, other apps and added parameters", () => {
  const ios = recommendOpenClaw({ mobilePlatform: "ios" }).companionUrl;
  const android = recommendOpenClaw({ mobilePlatform: "android" }).companionUrl;
  for (const url of [undefined, "javascript:alert(1)", ios.replace("apps.apple.com", "apps.apple.com.evil.example"),
    ios.replace("6780396132", "123456789"), android.replace("ai.openclaw.app", "other.app"),
    `${android}&redirect=evil`, recommendOpenClaw({ platform: "macos" }).downloadUrl]) {
    assert.equal(isOfficialOpenClawCompanion(url), false);
  }
  assert.equal(recommendOpenClaw({ mobile: true, mobilePlatform: "https://evil.example" }).companionUrl, null);
  assert.equal(recommendOpenClaw({ platform: "macos" }).companionUrl, null);
});

test("official downloads use independently pinned desktop releases", () => {
  const mac = recommendOpenClaw({ platform: "macos", architecture: "arm64" });
  const win = recommendOpenClaw({ platform: "windows", architecture: "x64" });
  const linux = recommendOpenClaw({ platform: "linux", architecture: "x64" });
  assert.equal(mac.version, "2026.9.7");
  assert.match(mac.downloadUrl, /\/OpenClaw-2026\.9\.7-arm64\.dmg$/);
  assert.equal(win.version, "2026.9.4");
  assert.match(win.downloadUrl, /^https:\/\/github\.com\/openclaw\/openclaw-windows-node\/releases\/download\/v2026\.9\.4\/OpenClawCompanion-Setup-x64\.exe$/);
  assert.equal(linux.version, "2026.9.5");
  assert.match(linux.downloadUrl, /-amd64\.AppImage$/);
  assert.match(linux.requirements, /glibc 2\.35/);
  assert.match(recommendOpenClaw({ platform: "linux", architecture: "x64", format: "deb" }).downloadUrl, /-amd64\.deb$/);
  for (const item of [mac, win, linux, ...mac.alternatives, ...linux.alternatives]) {
    assert.equal(isOfficialOpenClawDownload(item.downloadUrl), true);
    assert.match(item.docsUrl, /^https:\/\/docs\.openclaw\.ai\/platforms\//);
  }
});

test("Linux ARM64, unknown CPUs and 32-bit hints cannot choose an incompatible download", async () => {
  assert.equal(recommendOpenClaw({ platform: "linux", architecture: "arm64" }).supported, false);
  assert.equal(recommendOpenClaw({ platform: "linux" }).status, "choose-architecture");
  const device = await detectClientPlatform({ userAgentData: { platform: "Windows",
    async getHighEntropyValues() { return { architecture: "x86", bitness: "32" }; } } });
  assert.equal(device.architecture, "unknown");
  assert.equal(recommendOpenClaw(device).supported, false);
  assert.equal(recommendOpenClaw({ platform: "macos", architecture: "ia32" }).downloadUrl, null);
});

test("manual CPU choices work and RAM/GPU cannot change the desktop package", () => {
  const detected = { platform: "windows", architecture: "unknown", mobile: false };
  assert.equal(recommendOpenClaw(detected).downloadUrl, null);
  const selected = recommendOpenClaw({ ...detected, architecture: "arm64" });
  assert.match(selected.downloadUrl, /-arm64\.exe$/);
  assert.deepEqual(recommendOpenClaw({ ...detected, architecture: "arm64", memoryGB: 1, gpu: "small" }), selected);
  assert.deepEqual(recommendOpenClaw({ ...detected, architecture: "arm64", memoryGB: 128, gpu: "large" }), selected);
});

test("download allowlist rejects altered paths, unofficial hosts and executable URLs", () => {
  const url = recommendOpenClaw({ platform: "macos" }).downloadUrl;
  for (const candidate of [undefined, null, "javascript:alert(1)", "https://evil.example/OpenClaw.dmg",
    url.replace("github.com", "github.com.evil.example"), url.replace("openclaw/openclaw", "attacker/openclaw"),
    url.replace("v2026.9.7", "latest"), `${url}?redirect=evil`, `${url}#other`, ` ${url}`]) {
    assert.equal(isOfficialOpenClawDownload(candidate), false);
  }
  assert.equal(recommendOpenClaw({ platform: "https://evil.example", architecture: "x64" }).downloadUrl, null);
});
