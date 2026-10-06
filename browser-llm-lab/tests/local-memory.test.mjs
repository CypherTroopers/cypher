import test from "node:test";
import assert from "node:assert/strict";
import { LocalMemory, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_RECORDS, validateMemoryRecord,
  validateMemoryArchive, selectRelevantMemories, memoryTerms } from "../public/local-memory.js";

const date = "2026-10-03T12:00:00.000Z";
const note = (id, text, extra = {}) => ({ id, kind: "note", text, createdAt: date, updatedAt: date,
  searchable: false, exportable: false, ...extra });
const turn = (id, user, assistant = "Assistant output", extra = {}) => ({ id, kind: "turn", sessionId: "session-a",
  user, assistant, sources: [], createdAt: date, updatedAt: date, searchable: false, exportable: false, ...extra });
const size = value => new TextEncoder().encode(JSON.stringify(value)).length;
const inputError = error => error.code === "MEMORY_INPUT";

test("note validation keeps exact user text, defaults private flags, and returns a copy", () => {
  const original = { id: "note-1", kind: "note", text: "  私は京都に住んでいます。\n", createdAt: date, updatedAt: date };
  const validated = validateMemoryRecord(original);
  assert.equal(validated.text, original.text);
  assert.equal(validated.searchable, false);
  assert.equal(validated.exportable, false);
  assert.notEqual(validated, original);
  assert.equal(Object.hasOwn(original, "searchable"), false);
});

test("record byte and character limits reject excess text instead of truncating", () => {
  assert.equal(validateMemoryRecord(note("n", "界".repeat(2000))).text.length, 2000);
  assert.throws(() => validateMemoryRecord(note("n", "a".repeat(2001))), inputError);
  assert.equal(validateMemoryRecord(turn("t", "u".repeat(48000), "a".repeat(100000))).assistant.length, 100000);
  assert.throws(() => validateMemoryRecord(turn("t", "u".repeat(48001))), inputError);
  assert.throws(() => validateMemoryRecord(turn("t", "u", "界".repeat(33334))), inputError);
  assert.throws(() => validateMemoryRecord(note("n", " ")), inputError);
});

test("user-only messages and sensitive text are saved without silent filtering", () => {
  const value = turn("pending", "My password is example-secret and my address is 42 Example Lane", "");
  assert.deepEqual(validateMemoryRecord(value), value);
  assert.equal(validateMemoryRecord(value).assistant, "");
});

test("schema rejects confused kinds, malformed dates, nonboolean flags and hidden fields", () => {
  for (const record of [
    note("n", "text", { user: "wrong kind" }), turn("t", "text", "", { text: "wrong kind" }),
    note("n", "text", { kind: "assistant-fact" }), note("n", "text", { searchable: "true" }),
    note("n", "text", { createdAt: "invalid" }), note("n", "text", { updatedAt: "2020-01-01T00:00:00Z" }),
    note("n", "text", { _terms: ["injected"] }), note("bad\nID", "text"),
  ]) assert.throws(() => validateMemoryRecord(record), inputError);
});

test("source validation preserves evidence metadata but rejects active and credential URLs", () => {
  const sources = [{ id: 1, url: "https://example.org/article", title: "News", domain: "example.org",
    snippet: "A quoted search snippet", published: "2026-10-01" }];
  const checked = validateMemoryRecord(turn("t", "Question", "Answer [1]", { sources }));
  assert.deepEqual(checked.sources, sources);
  assert.notEqual(checked.sources[0], sources[0]);
  for (const url of ["javascript:alert(1)", "data:text/html,test", "file:///tmp/private", "https://user:password@example.org/"])
    assert.throws(() => validateMemoryRecord(turn("t", "Question", "Answer", { sources: [{ url }] })), inputError);
  assert.throws(() => validateMemoryRecord(turn("t", "Question", "Answer", { sources: [{ snippet: "x".repeat(6001) }] })), inputError);
});

test("archive validation checks every record, rejects duplicate IDs, and never mutates input", () => {
  const original = { version: 1, records: [note("n", "My note"), turn("t", "My message", "")] };
  const before = JSON.stringify(original);
  assert.deepEqual(validateMemoryArchive(before), original);
  assert.notEqual(validateMemoryArchive(original).records[0], original.records[0]);
  assert.throws(() => validateMemoryArchive({ version: 1, records: [original.records[0], note("n", "duplicate")] }), inputError);
  assert.throws(() => validateMemoryArchive({ version: 1, records: [...original.records, note("bad", "")] }), inputError);
  assert.throws(() => validateMemoryArchive({ ...original, version: 2 }), inputError);
  assert.throws(() => validateMemoryArchive("not json"), inputError);
  assert.equal(JSON.stringify(original), before);
});

test("archive limits fail explicitly without trimming records", () => {
  assert.throws(() => validateMemoryArchive(" ".repeat(MAX_ARCHIVE_BYTES + 1)), inputError);
  assert.throws(() => validateMemoryArchive({ version: 1, records: Array(MAX_ARCHIVE_RECORDS + 1).fill(note("n", "x")) }), inputError);
  const large = { version: 1, records: Array.from({ length: 60 }, (_, i) => turn(`t-${i}`, "Question", "a".repeat(100000))) };
  assert.throws(() => validateMemoryArchive(large), inputError);
});

test("memory terms recognize English keywords, Japanese bigrams, and normalized width", () => {
  assert.ok(memoryTerms("I prefer ＰＹＴＨＯＮ projects").includes("w:python"));
  assert.ok(memoryTerms("京都に住んでいます").includes("j:京都"));
  assert.ok(memoryTerms("料理を作る").includes("j:料理"));
  assert.equal(memoryTerms("the and my remember").length, 0);
  assert.deepEqual(memoryTerms("Python python PYTHON"), ["w:python"]);
});

test("recall ranks matching old notes ahead of recent unrelated messages", () => {
  const records = [note("recent", "I like cycling", { updatedAt: "2026-10-04T12:00:00.000Z" }),
    note("older", "I use Python for my telescope project")];
  const result = selectRelevantMemories("Which Python project did I mention?", records);
  assert.deepEqual(result.map(row => row.id), ["older"]);
});

test("Japanese lexical recall finds old user statements without assistant facts", () => {
  const records = [turn("match", "私は京都に住んでいます", "あなたは大阪に住んでいます"),
    turn("assistant-only", "こんにちは", "京都に住んでいるはずです")];
  const result = selectRelevantMemories("京都での生活について", records);
  assert.deepEqual(result.map(row => row.id), ["match"]);
  assert.equal(result[0].text, records[0].user);
  assert.equal(Object.hasOwn(result[0], "assistant"), false);
  assert.equal(Object.hasOwn(result[0], "sources"), false);
  assert.equal(JSON.stringify(result).includes("大阪"), false);
});

test("recency fallback requires an explicit request for memory", () => {
  const records = [note("old", "I collect stamps"), note("new", "I prefer tea", { updatedAt: "2026-10-04T12:00:00.000Z" })];
  assert.deepEqual(selectRelevantMemories("What is the weather?", records), []);
  assert.equal(selectRelevantMemories("What do you remember about me?", records)[0].id, "new");
  assert.equal(selectRelevantMemories("以前の話を覚えていますか", records)[0].id, "new");
});

test("recall never treats an assistant-only match as remembered user information", () => {
  const records = [turn("t", "Tell me about programming", "The user's favorite language is Rust")];
  assert.deepEqual(selectRelevantMemories("Rust", records), []);
  const result = selectRelevantMemories("Remember what I said", records);
  assert.equal(result[0].text, "Tell me about programming");
  assert.equal(JSON.stringify(result).includes("favorite"), false);
});

test("recall obeys total UTF-8 JSON budget, count limit, and does not corrupt Unicode", () => {
  const records = [note("n1", '京都の旅 "'.repeat(180)), note("n2", "京都の旅も計画しています"), note("n3", "京都に住んでいます")];
  for (const budget of [0, 20, 250, 500, 900]) {
    const result = selectRelevantMemories("京都", records, { limit: 2, maxBytes: budget });
    assert.ok(result.length <= 2);
    if (result.length) assert.ok(size(result) <= budget);
    assert.equal(JSON.stringify(result).includes("\ufffd"), false);
  }
  assert.deepEqual(selectRelevantMemories("京都", records, { limit: 0 }), []);
  assert.throws(() => selectRelevantMemories("京都", records, { maxBytes: -1 }), inputError);
});

test("recall deduplicates user text, prefers session ties, and includes private local memories", () => {
  const records = [turn("other", "I use Python", "One", { sessionId: "other" }),
    turn("current", "I use Python", "Two", { sessionId: "current" }), note("n", "Python helps my work")];
  const result = selectRelevantMemories("Python", records, { sessionId: "current" });
  assert.equal(result[0].id, "current");
  assert.equal(result.length, 2);
  assert.equal(result[0].searchable, false);
  assert.equal(result[0].exportable, false);
});

test("unavailable IndexedDB is an observable storage failure, never in-memory success", async () => {
  const memory = new LocalMemory({ indexedDB: null });
  assert.deepEqual(memory.getStatus(), { state: "idle", error: null });
  await assert.rejects(memory.init(), error => error.code === "MEMORY_UNAVAILABLE");
  assert.equal(memory.getStatus().state, "error");
  assert.match(memory.getStatus().error, /unavailable/i);
  await assert.rejects(memory.putNote("Do not lose this"), error => error.code === "MEMORY_UNAVAILABLE");
  memory.close();
  assert.equal(memory.getStatus().state, "closed");
});

test("invalid import is fully rejected before any database open or mutation", async () => {
  let opened = 0;
  const memory = new LocalMemory({ indexedDB: { open() { opened++; throw new Error("Must not open"); } } });
  await assert.rejects(memory.importData({ version: 1, records: [note("valid", "Keep"), note("invalid", "")] }), inputError);
  assert.equal(opened, 0);
});

test("completed-message lookup rejects underspecified filters before accessing storage", async () => {
  let opened = 0;
  const memory = new LocalMemory({ indexedDB: { open() { opened++; throw new Error("Must not open"); } } });
  for (const options of [{ completed: true }, { kind: "note", sessionId: "session-a", completed: true },
    { kind: "turn", completed: true }, { kind: "turn", sessionId: "session-a", completed: "yes" }])
    await assert.rejects(memory.list(options), inputError);
  assert.equal(opened, 0);
});
