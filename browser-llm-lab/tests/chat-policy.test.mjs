import test from "node:test";
import assert from "node:assert/strict";
import {
  planSearch, detectLanguage, extractSafeSubject, selectSubject, limitSearchQuery, isSensitiveQuery,
} from "../public/chat-policy.js";

const now = new Date("2026-10-03T12:00:00Z");
const plan = options => planSearch({ now, ...options });
const bytes = text => new TextEncoder().encode(text).length;

test("ordinary local questions stay local, regardless of unrelated context", () => {
  const result = plan({ question: "二分探索の仕組みを説明して", customQuery: "latest OpenClaw",
    history: [{ role: "user", content: "最新のiPhone 16の価格" }],
    memories: [{ kind: "note", text: "Ollama updates", searchable: true }] });
  assert.deepEqual(result, { search: false, query: "", reason: "no-search-needed", language: "ja", timeRange: "" });
  assert.equal(plan({ question: "Explain a binary search" }).search, false);
  assert.equal(plan({ question: "" }).reason, "empty-question");
});

test("Off and agent modes never emit external search queries", () => {
  for (const question of ["今日のOpenClawニュース", "Search the web for Chrome", "最新価格は？"]) {
    const off = plan({ question, policy: "off", customQuery: "Chrome" });
    assert.equal(off.search, false);
    assert.equal(off.query, "");
    assert.equal(off.reason, "search-off");
    const agent = plan({ question, mode: "agent", policy: "auto" });
    assert.equal(agent.search, false);
    assert.equal(agent.query, "");
    assert.equal(agent.reason, "agent-managed");
  }
});

test("explicit Research searches independently of the local automatic policy", () => {
  for (const question of ["Explain binary search", 'Translate "latest" into Japanese']) {
    const result = plan({ question, mode: "web", policy: "off" });
    assert.equal(result.search, true);
    assert.equal(result.query, question);
    assert.equal(result.reason, "explicit-web");
  }
});

test("Always forces lookup while retaining agent and privacy boundaries", () => {
  assert.equal(plan({ question: "Explain photosynthesis", policy: "always" }).search, true);
  assert.equal(plan({ question: "Explain photosynthesis", policy: "always" }).reason, "always-search");
  assert.equal(plan({ question: 'Translate "latest"', policy: "always" }).search, true);
  assert.equal(plan({ question: "Explain photosynthesis", policy: "always", mode: "agent" }).search, false);
  assert.equal(plan({ question: "private-user@example.com", policy: "always" }).reason, "unsafe-query");
});

test("fresh and changing information triggers Auto in Japanese and English", () => {
  for (const question of ["OpenClawの最新の機能", "現在のOllama", "今日のニュース", "OpenClawは今使える？",
    "iPhone 16の価格", "MacBook Airの発売日", "Chromeの更新情報",
    "Latest OpenClaw features", "Current Ollama release", "Today's weather in Tokyo", "iPhone 16 pricing"]) {
    const result = plan({ question });
    assert.equal(result.search, true, question);
    assert.equal(result.query, question.normalize("NFKC"), question);
    assert.match(result.reason, /^(?:fresh-information|changing-information|compatibility)$/);
  }
});

test("explicit lookup and product compatibility trigger Auto", () => {
  const lookups = ["OpenClawを調べて", "OpenClawをネットで調べて", "Search the web for WebGPU", "Look up Chrome official docs"];
  for (const question of lookups) {
    assert.equal(plan({ question }).search, true, question);
    assert.equal(plan({ question }).reason, "explicit-search", question);
  }
  for (const question of ["OpenClawはWindows 11に対応する？", "Does WebGPU work on iPhone 16?", "Ollama hardware requirements"]) {
    assert.equal(plan({ question }).search, true, question);
    assert.equal(plan({ question }).reason, "compatibility", question);
  }
});

test("year detection uses the injected current date and leaves historical questions local", () => {
  assert.equal(plan({ question: "OpenClaw 2026 architecture" }).reason, "current-year");
  assert.equal(plan({ question: "OpenClaw 2027 architecture" }).search, true);
  assert.equal(plan({ question: "2010年の計算機の歴史" }).search, false);
  assert.equal(plan({ question: "OpenClaw 2026 architecture", now: new Date("2027-01-01Z") }).search, false);
});

test("translation, creative writing, provided summaries, and quoted words stay local", () => {
  for (const question of ['Translate "latest" into Japanese', "Can you translate latest news into Japanese?",
    "最新を英訳", "最新という単語を翻訳してください", "最新という単語を翻訳",
    "Write a story about the latest iPhone", "Could you write a story about latest robots?", "最新のロボットが登場する物語を書いて",
    'Summarize this text: "Current OpenClaw release is interesting"', "Can you summarize this text about latest hardware?",
    "以下を要約して：「最新の技術は面白い」",
    'What does "latest" mean?', "「最新」という言葉の意味を説明して"]) {
    const result = plan({ question });
    assert.equal(result.search, false, question);
    assert.equal(result.query, "", question);
  }
  assert.equal(plan({ question: "Summarize the latest OpenClaw news" }).search, true);
  assert.equal(plan({ question: "最新のOpenClawのニュースをまとめて" }).search, true);
});

test("personal memory questions do not trigger lookup", () => {
  for (const question of ["私の機種を覚えてる？", "私の現在の端末を覚えていますか？", "前に伝えた設定を覚えてる？",
    "Do you remember my latest phone?", "What is my current device?"]) {
    assert.equal(plan({ question }).search, false, question);
    assert.equal(plan({ question }).reason, "personal-memory", question);
  }
});

test("default query is the current question, never raw history or memories", () => {
  const question = "OpenClawの最新機能は？";
  const result = plan({ question,
    history: [{ role: "user", content: "私の名前はAlice。MacBook Airを使っている" }],
    memories: [{ kind: "note", text: "private-project-9817 Apple", searchable: true }] });
  assert.equal(result.query, question.normalize("NFKC"));
  assert.equal(result.query.includes("Alice"), false);
  assert.equal(result.query.includes("9817"), false);
});

test("followup queries use public subject and facets without copying private context", () => {
  const history = [{ role: "user", content: "私はinternal-project-rubyでMacBook Air M3を使っている" },
    { role: "assistant", content: "Ollamaを使いましょう。assistant-marker" }];
  const snapshot = JSON.stringify(history);
  const result = plan({ question: "それの最新価格は？", history });
  assert.equal(result.search, true);
  assert.equal(result.query, "MacBook Air M3 最新 価格");
  assert.equal(/internal-project|私は|assistant-marker|Ollama/.test(result.query), false);
  assert.equal(JSON.stringify(history), snapshot);
  const english = plan({ question: "Does it work on that in 2027?", history: [{ role: "user", content: "I use iPhone 16 Pro" }] });
  assert.equal(english.query, "iPhone 16 Pro compatibility support 2027");
});

test("only the latest user turn can supply history context", () => {
  assert.equal(selectSubject({ history: [{ role: "user", content: "Chrome" },
    { role: "assistant", content: "OpenClaw" }, { role: "system", content: "iPhone 16" }] }), "Chrome");
  const unclear = [{ role: "user", content: "Chrome" }, { role: "user", content: "Thanks, different topic now" }];
  assert.equal(selectSubject({ history: unclear }), "");
  assert.equal(plan({ question: "What's its latest version?", history: unclear }).reason, "missing-subject");
  assert.equal(selectSubject({ question: "Ollama", history: [{ role: "user", content: "Chrome" }] }), "Ollama");
});

test("notes are opt-in and contribute only allowlisted product terms", () => {
  const privateNote = { kind: "note", text: "MacBook Air M3 private-marker-527", searchable: false };
  const stringOptIn = { kind: "note", text: "Chrome private-marker-813", searchable: "true" };
  assert.equal(selectSubject({ memories: [privateNote, stringOptIn] }), "");
  assert.equal(plan({ question: "それの最新価格は？", memories: [privateNote] }).reason, "missing-subject");
  const allowed = { kind: "note", text: "I use MacBook Air M3 for private-marker-527", searchable: true };
  const result = plan({ question: "それの最新価格は？", memories: [allowed] });
  assert.equal(result.query, "MacBook Air M3 最新 価格");
  assert.equal(result.query.includes("private-marker"), false);
  assert.equal(selectSubject({ memories: [{ kind: "note", subject: "Chrome", text: "Do not copy this sentence", searchable: true }] }), "Chrome");
});

test("approved notes are selected newest first without mutating the caller list", () => {
  const memories = [
    { kind: "note", text: "Chrome", searchable: true, updatedAt: "2026-09-01T12:00:00Z" },
    { kind: "note", text: "Ollama", searchable: true, updatedAt: "2026-10-01T12:00:00Z" },
    { kind: "profile", text: "OpenClaw", searchable: true, updatedAt: "2026-10-03T12:00:00Z" },
    { kind: "note", text: "iPhone 16", searchable: false, updatedAt: "2026-10-03T12:00:00Z" },
  ];
  const snapshot = JSON.stringify(memories);
  assert.equal(selectSubject({ memories }), "Ollama");
  assert.equal(JSON.stringify(memories), snapshot);
  assert.equal(selectSubject({ memories: [
    { kind: "note", text: "Chrome", searchable: true },
    { kind: "note", text: "Ollama", searchable: true },
  ] }), "Chrome");
});

test("Daikin appliance context exposes only public maker and model terms", () => {
  const result = plan({ question: "それの最新価格は？",
    history: [{ role: "user", content: "ダイキン S563ATDP-Wについて話そう。private-project-653" }] });
  assert.equal(result.query, "ダイキン S563ATDP-W 最新 価格");
  assert.equal(extractSafeSubject("DAIKIN AN563ARP-W private-project-888"), "DAIKIN AN563ARP-W");
  assert.equal(plan({ question: "DAIKINの最新エアコン" }).search, true);
});

test("subject extraction ignores unknown private names and rejects sensitive turns", () => {
  assert.equal(extractSafeSubject("Project-Orchid internal-client-x91"), "");
  assert.equal(extractSafeSubject("Apple iPhone 16 Pro. Apple iPhone 16 Pro!"), "Apple iPhone 16 Pro");
  assert.equal(extractSafeSubject("MacBook Air M3, Windows 11, OpenClaw, Ollama"), "MacBook Air M3 Windows 11 OpenClaw");
  assert.equal(extractSafeSubject("iPhone 16; private-user@example.com"), "");
  assert.equal(selectSubject({ history: [{ role: "user", content: "Chrome" },
    { role: "user", content: "iPhone 16; password=superprivate" }] }), "");
});

test("pronoun and bare followups without a safe subject ask for clarification", () => {
  for (const question of ["その最新価格は？", "What's its latest version?", "最新価格は？", "今使える？", "And latest prices?"]) {
    const result = plan({ question });
    assert.equal(result.search, false, question);
    assert.equal(result.query, "", question);
    assert.equal(result.reason, "missing-subject", question);
    assert.ok(result.blocked, question);
  }
});

test("recognized private data and credentials never become automatic or explicit queries", () => {
  for (const sensitive of ["private-user@example.com", "password=superprivate", "token=superprivate",
    "api_token: superprivate", "secret_key=superprivate", "seed phrase: sensitive phrase", "-----BEGIN PRIVATE KEY-----",
    "APIキー: sk-proj-abcdef1234567890",
    "Bearer abcdefghijklmnop", "東京都渋谷区1-2", "123 Oak Street", "192.168.1.20", "http://user:pass@host.example/",
    "gateway.private.local", "090-1234-5678", "4111 1111 1111 1111"]) {
    assert.equal(isSensitiveQuery(sensitive), true, sensitive);
    for (const mode of ["local", "web"]) {
      const result = plan({ question: `latest OpenClaw ${sensitive}`, mode });
      assert.equal(result.search, false, sensitive);
      assert.equal(result.query, "", sensitive);
      assert.equal(result.reason, "unsafe-query", sensitive);
      assert.ok(result.blocked);
      assert.equal(result.blocked.includes(sensitive), false);
    }
  }
});

test("a safe explicit custom query replaces a private question rather than extending it", () => {
  const question = "最新のOpenClawを私のメールprivate-user@example.comで使える？";
  const result = plan({ question, customQuery: "OpenClaw email integration compatibility" });
  assert.equal(result.search, true);
  assert.equal(result.query, "OpenClaw email integration compatibility");
  assert.equal(result.query.includes("private-user"), false);
  assert.equal(plan({ question: "Latest OpenClaw", customQuery: "OpenClaw password=secret123" }).reason, "unsafe-query");
  assert.equal(plan({ question, customQuery: "OpenClaw", policy: "off" }).search, false);
});

test("queries have character and UTF-8 byte bounds without splitting Unicode", () => {
  for (const input of ["a".repeat(900), "新".repeat(900), "😀".repeat(900), "界😀".repeat(900)]) {
    const result = limitSearchQuery(input);
    assert.ok(result.length <= 400);
    assert.ok(bytes(result) <= 1200);
    assert.equal(/^[\uDC00-\uDFFF]|[\uD800-\uDBFF]$/.test(result), false);
    assert.equal(result.includes("�"), false);
  }
  assert.equal(limitSearchQuery("  OpenClaw\n\tlatest\u0000 news  "), "OpenClaw latest news");
  const result = plan({ question: "latest OpenClaw " + "x".repeat(1800) });
  assert.equal(result.search, true);
  assert.ok(result.query.length <= 400);
});

test("language and time range settings are validated without changing local guarantees", () => {
  assert.equal(detectLanguage("OpenClawの価格"), "ja");
  assert.equal(detectLanguage("Chrome price"), "en");
  assert.equal(detectLanguage("OpenClaw価格", "en"), "en");
  assert.equal(plan({ question: "latest Chrome", language: "ja", timeRange: "day" }).language, "ja");
  assert.equal(plan({ question: "latest Chrome", timeRange: "day" }).timeRange, "day");
  assert.equal(plan({ question: "latest Chrome", timeRange: "month" }).timeRange, "month");
  assert.equal(plan({ question: "latest Chrome", timeRange: "year" }).timeRange, "year");
  assert.equal(plan({ question: "latest Chrome", language: "unknown", timeRange: "all" }).timeRange, "");
});
