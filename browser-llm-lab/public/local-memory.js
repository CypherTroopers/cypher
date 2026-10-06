// Local-only conversation storage. Search metadata never authorizes a network request.
export const MEMORY_DATABASE = "cypher-memory-v1";
export const MEMORY_VERSION = 1;
export const MAX_ARCHIVE_BYTES = 5 * 1024 * 1024;
export const MAX_ARCHIVE_RECORDS = 10000;
const encoder = new TextEncoder();
const byteLength = value => encoder.encode(value).length;
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const plain = value => value !== null && typeof value === "object" && !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
function failure(code, message) { return Object.assign(new Error(message), { code }); }
function requireValue(condition, message) { if (!condition) throw failure("MEMORY_INPUT", message); }
function fields(value, allowed, label) {
  requireValue(plain(value), `${label} must be an object.`);
  requireValue(Object.keys(value).every(key => allowed.includes(key)), `${label} contains an unsupported field.`);
}
function textValue(value, label, maxBytes, maxChars = maxBytes, allowEmpty = false) {
  requireValue(typeof value === "string" && (allowEmpty || value.trim().length > 0), `${label} must be text.`);
  requireValue(value.length <= maxChars && byteLength(value) <= maxBytes, `${label} exceeds its storage limit.`);
  return value;
}
function identifier(value, label) {
  const result = textValue(value, label, 800, 200);
  requireValue(!/[\u0000-\u001f\u007f]/u.test(result), `${label} contains control characters.`);
  return result;
}
function timestamp(value, label) {
  requireValue(typeof value === "string" || typeof value === "number", `${label} must be a timestamp.`);
  const date = new Date(value);
  requireValue(Number.isFinite(date.getTime()) && date.getUTCFullYear() >= 1970 && date.getUTCFullYear() <= 9999,
    `${label} is invalid.`);
  return date.toISOString();
}
function flag(value, key) {
  requireValue(!own(value, key) || typeof value[key] === "boolean", `${key} must be true or false.`);
  return value[key] ?? false;
}
function sourceRecord(source) {
  fields(source, ["id", "url", "title", "domain", "snippet", "published", "retrieved_at", "retrievedAt"], "Source");
  const result = {};
  for (const [key, value] of Object.entries(source)) {
    if (key === "id") {
      requireValue((Number.isSafeInteger(value) && value >= 0) || (typeof value === "string" && value.length <= 100), "Invalid source ID.");
      result[key] = value;
    } else {
      result[key] = textValue(value, `Source ${key}`, key === "snippet" ? 6000 : key === "url" ? 4096 : 2000, undefined, true);
    }
  }
  if (result.url) {
    let url;
    try { url = new URL(result.url); } catch { throw failure("MEMORY_INPUT", "Invalid source URL."); }
    requireValue(["https:", "http:"].includes(url.protocol) && !url.username && !url.password,
      "Source URLs must use HTTP(S) without credentials.");
  }
  return result;
}

// Validation returns a new, JSON-safe record and never changes its input.
export function validateMemoryRecord(value) {
  fields(value, ["id", "kind", "createdAt", "updatedAt", "searchable", "exportable", "text",
    "sessionId", "user", "assistant", "sources"], "Memory record");
  requireValue(value.kind === "note" || value.kind === "turn", "Unknown memory record kind.");
  const record = { id: identifier(value.id, "Record ID"), kind: value.kind,
    createdAt: timestamp(value.createdAt, "Created time"), updatedAt: timestamp(value.updatedAt, "Updated time"),
    searchable: flag(value, "searchable"), exportable: flag(value, "exportable") };
  requireValue(record.updatedAt >= record.createdAt, "Updated time cannot precede created time.");
  if (value.kind === "note") {
    requireValue(!["sessionId", "user", "assistant", "sources"].some(key => own(value, key)), "A note cannot contain conversation fields.");
    record.text = textValue(value.text, "Note", 6000, 2000);
  } else {
    requireValue(!own(value, "text"), "A conversation cannot contain a note field.");
    record.sessionId = identifier(value.sessionId, "Session ID");
    record.user = textValue(value.user, "User message", 48000);
    record.assistant = textValue(value.assistant, "Assistant message", 100000, 100000, true);
    requireValue(!own(value, "sources") || (Array.isArray(value.sources) && value.sources.length <= 20), "Use at most 20 sources per turn.");
    record.sources = (value.sources || []).map(sourceRecord);
  }
  requireValue(byteLength(JSON.stringify(record)) <= 180000, "Memory record exceeds its total storage limit.");
  return record;
}

export function validateMemoryArchive(data) {
  let value = data;
  if (typeof data === "string") {
    requireValue(byteLength(data) <= MAX_ARCHIVE_BYTES, "Memory archive exceeds 5 MiB.");
    try { value = JSON.parse(data); } catch { throw failure("MEMORY_INPUT", "Memory archive is not valid JSON."); }
  }
  fields(value, ["version", "records"], "Memory archive");
  requireValue(value.version === MEMORY_VERSION, "Unsupported memory archive version.");
  requireValue(Array.isArray(value.records) && value.records.length <= MAX_ARCHIVE_RECORDS,
    "Memory archive must contain at most 10,000 records.");
  const records = [], ids = new Set();
  let bytes = byteLength(JSON.stringify({ version: MEMORY_VERSION, records: [] }));
  for (const valueRecord of value.records) {
    const record = validateMemoryRecord(valueRecord);
    requireValue(!ids.has(record.id), "Memory archive contains duplicate record IDs.");
    bytes += byteLength(JSON.stringify(record)) + (records.length ? 1 : 0);
    requireValue(bytes <= MAX_ARCHIVE_BYTES, "Memory archive exceeds 5 MiB.");
    records.push(record);
    ids.add(record.id);
  }
  return { version: MEMORY_VERSION, records };
}

const STOP_WORDS = new Set(("a an and are as at be been being but by can could did do does for from had has have how i if in into is it its " +
  "me my of on or our please so that the their them there these they this those to was we were what when where which who why will with would you your " +
  "remember recall previously earlier memory told said discussed").split(" "));
const JAPANESE_STOP = new Set(["です", "ます", "した", "して", "ない", "こと", "これ", "それ", "その", "この", "から", "まで", "につ", "つい", "いて", "には", "では", "ので", "のは", "とは", "たい", "よう", "する", "あり", "れて"]);
export function memoryTerms(text) {
  const normalized = String(text || "").normalize("NFKC").toLowerCase();
  const terms = new Set();
  for (const word of normalized.match(/[a-z0-9][a-z0-9_-]+/gu) || []) {
    if (!STOP_WORDS.has(word)) terms.add(`w:${word}`);
  }
  for (const chunk of normalized.match(/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}ー]+/gu) || []) {
    const chars = [...chunk];
    if (chars.length === 1 && /\p{Script=Han}/u.test(chunk)) terms.add(`j:${chunk}`);
    for (let i = 0; i < chars.length - 1; i++) {
      const pair = chars[i] + chars[i + 1];
      if (!JAPANESE_STOP.has(pair)) terms.add(`j:${pair}`);
    }
  }
  return [...terms];
}
const asksForMemory = question => /\b(remember|recall|previously|earlier|last\s+(time|conversation)|what\s+(?:did\s+)?i\s+(?:say|tell|said))\b|覚え|記憶|前に|以前|前回|さっき|過去|話した|伝えた|私について/u.test(String(question).toLowerCase());
const newestFirst = (a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id);
function clipBytes(text, budget) {
  let result = "", used = 0;
  for (const char of text) {
    const size = byteLength(char);
    if (used + size > budget) break;
    result += char; used += size;
  }
  return result;
}

// This is lexical recall, not a factual or semantic verification step. Assistant
// output and search snippets are deliberately excluded from recall and indexing.
export function selectRelevantMemories(question, records, { limit = 4, maxBytes = 900, sessionId } = {}) {
  requireValue(Number.isInteger(limit) && limit >= 0 && limit <= 100, "Invalid recall limit.");
  requireValue(Number.isInteger(maxBytes) && maxBytes >= 0 && maxBytes <= 48000, "Invalid recall byte budget.");
  const terms = memoryTerms(question), fallback = asksForMemory(question);
  const ranked = [];
  for (const record of records) {
    if (!record || !["note", "turn"].includes(record.kind)) continue;
    const text = record.kind === "note" ? record.text : record.user;
    if (typeof text !== "string" || !text.trim()) continue;
    const available = new Set(memoryTerms(text));
    const matches = terms.reduce((score, term) => score + (available.has(term) ? (term.startsWith("w:") ? 2 : 1) : 0), 0);
    if (!matches && !fallback) continue;
    ranked.push({ record, text, score: matches + (sessionId && record.sessionId === sessionId ? .1 : 0) });
  }
  ranked.sort((a, b) => b.score - a.score || newestFirst(a.record, b.record));
  const result = [], seen = new Set();
  for (const { record, text } of ranked) {
    if (result.length >= limit) break;
    const key = text.normalize("NFKC").trim().toLowerCase();
    if (seen.has(key)) continue;
    const selected = { id: record.id, kind: record.kind, text, createdAt: record.createdAt,
      updatedAt: record.updatedAt, searchable: record.searchable === true, exportable: record.exportable === true };
    const room = maxBytes - byteLength(JSON.stringify([...result, { ...selected, text: "" }])) - 4;
    if (room <= 0) continue;
    selected.text = clipBytes(text, room);
    // JSON escaping may use more bytes than the original text.
    while (selected.text && byteLength(JSON.stringify([...result, selected])) > maxBytes)
      selected.text = clipBytes(selected.text, Math.max(0, byteLength(selected.text) - 8));
    if (!selected.text.trim()) continue;
    result.push(selected); seen.add(key);
  }
  return result;
}

const storedRecord = record => ({ ...record, _terms: memoryTerms(record.kind === "note" ? record.text : record.user),
  _completed: record.kind === "turn" && record.assistant.trim() ? 1 : 0 });
const publicRecord = record => { const { _terms, _completed, ...value } = record; return value; };
const newId = () => globalThis.crypto?.randomUUID?.() || `memory-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;

export class LocalMemory {
  constructor({ indexedDB = globalThis.indexedDB, IDBKeyRange = globalThis.IDBKeyRange } = {}) {
    this.factory = indexedDB; this.keyRange = IDBKeyRange;
    this.db = null; this.opening = null; this.generation = 0;
    this.status = { state: "idle", error: null };
  }
  getStatus() { return { ...this.status }; }
  problem(error) {
    const cause = error instanceof Error ? error : new Error(String(error || "Local memory storage failed."));
    this.status = { state: "error", error: cause.message };
    return cause;
  }
  async init() {
    if (this.db) return this;
    if (this.opening) return this.opening;
    if (!this.factory) throw this.problem(failure("MEMORY_UNAVAILABLE", "IndexedDB is unavailable. Local memory could not be saved."));
    const generation = ++this.generation;
    this.opening = new Promise((resolve, reject) => {
      let request, rejected = false;
      const fail = error => { rejected = true; reject(this.problem(error)); };
      try { request = this.factory.open(MEMORY_DATABASE, MEMORY_VERSION); }
      catch (error) { fail(error); return; }
      request.onupgradeneeded = () => {
        try {
          const db = request.result;
          const store = db.createObjectStore("records", { keyPath: "id" });
          store.createIndex("updatedAt", "updatedAt");
          store.createIndex("kindUpdatedAt", ["kind", "updatedAt"]);
          store.createIndex("sessionUpdatedAt", ["sessionId", "updatedAt"]);
          store.createIndex("sessionCompletedAt", ["sessionId", "_completed", "updatedAt"]);
          store.createIndex("terms", "_terms", { multiEntry: true });
        } catch (error) { request.transaction.abort(); fail(error); }
      };
      request.onerror = () => fail(request.error || new Error("Could not open local memory."));
      request.onblocked = () => fail(failure("MEMORY_BLOCKED", "Another tab is blocking local memory. Close that tab and retry."));
      request.onsuccess = () => {
        const db = request.result;
        if (rejected || generation !== this.generation) {
          db.close();
          if (!rejected) reject(failure("MEMORY_CLOSED", "Local memory was closed before it opened."));
          return;
        }
        db.onversionchange = () => { this.close(); this.status = { state: "closed", error: "Local memory changed in another tab. Reopen it to continue." }; };
        db.onclose = () => { if (this.db === db) { this.db = null; this.status = { state: "closed", error: "Local memory storage closed unexpectedly." }; } };
        this.db = db; this.status = { state: "ready", error: null }; resolve(this);
      };
    });
    try { return await this.opening; } finally { this.opening = null; }
  }
  close() {
    this.generation++;
    this.db?.close(); this.db = null;
    this.status = { state: "closed", error: null };
  }
  async transaction(mode, work) {
    await this.init();
    return new Promise((resolve, reject) => {
      let tx, result, cause;
      try { tx = this.db.transaction("records", mode); }
      catch (error) { reject(this.problem(error)); return; }
      const abort = error => { cause = error; try { tx.abort(); } catch { reject(this.problem(error)); } };
      const guard = callback => event => { try { callback(event); } catch (error) { abort(error); } };
      tx.oncomplete = () => { this.status = { state: "ready", error: null }; resolve(result); };
      tx.onabort = () => reject(this.problem(cause || tx.error || new Error("Local memory transaction was aborted.")));
      tx.onerror = () => { cause ||= tx.error; };
      try { work(tx.objectStore("records"), value => { result = value; }, guard); }
      catch (error) { abort(error); }
    });
  }
  async list({ kind, limit = 100, sessionId, completed } = {}) {
    requireValue(kind === undefined || ["note", "turn"].includes(kind), "Invalid memory kind.");
    requireValue(Number.isInteger(limit) && limit >= 0 && limit <= 10000, "Invalid memory list limit.");
    if (sessionId !== undefined) identifier(sessionId, "Session ID");
    requireValue(completed === undefined || (typeof completed === "boolean" && kind === "turn" && sessionId !== undefined),
      "Completed-message lookup requires a conversation kind and session ID.");
    if (!limit) return [];
    return this.transaction("readonly", (store, set, guard) => {
      const records = [];
      const field = completed !== undefined ? "sessionCompletedAt" : sessionId !== undefined ? "sessionUpdatedAt" : kind ? "kindUpdatedAt" : "updatedAt";
      const prefix = completed !== undefined ? [sessionId, completed ? 1 : 0] : sessionId !== undefined || kind ? [sessionId ?? kind] : null;
      const range = prefix ? this.keyRange.bound([...prefix, ""], [...prefix, "\uffff"]) : null;
      const request = store.index(field).openCursor(range, "prev");
      request.onsuccess = guard(() => {
        const cursor = request.result;
        if (!cursor || records.length >= limit) { set(records); return; }
        if (!kind || cursor.value.kind === kind) records.push(publicRecord(cursor.value));
        if (records.length >= limit) set(records); else cursor.continue();
      });
    });
  }
  async getStats() {
    return this.transaction("readonly", (store, set, guard) => {
      const request = store.count(); request.onsuccess = guard(() => set({ count: request.result }));
    });
  }
  async putNote(text, { id = newId(), searchable = false } = {}) {
    const now = new Date().toISOString();
    const note = validateMemoryRecord({ id, kind: "note", text, createdAt: now, updatedAt: now, searchable, exportable: false });
    return this.putRecord(note);
  }
  async saveTurn({ id = newId(), sessionId, user, assistant, sources = [], createdAt = new Date().toISOString() }) {
    const created = timestamp(createdAt, "Created time");
    const turn = validateMemoryRecord({ id, kind: "turn", sessionId, user, assistant, sources,
      createdAt: created, updatedAt: new Date(Math.max(Date.now(), new Date(created).getTime())).toISOString(), searchable: false, exportable: false });
    return this.putRecord(turn);
  }
  async putRecord(record) {
    return this.transaction("readwrite", (store, set, guard) => {
      const request = store.get(record.id);
      request.onsuccess = guard(() => {
        const previous = request.result;
        requireValue(!previous || previous.kind === record.kind, "This record ID belongs to a different memory kind.");
        const next = validateMemoryRecord({ ...record, createdAt: previous?.createdAt || record.createdAt,
          updatedAt: previous && previous.updatedAt > record.updatedAt ? previous.updatedAt : record.updatedAt });
        store.put(storedRecord(next)); set(next);
      });
    });
  }
  async remove(id) {
    identifier(id, "Record ID");
    return this.transaction("readwrite", store => { store.delete(id); });
  }
  async clear() { return this.transaction("readwrite", store => { store.clear(); }); }
  async exportData() {
    const records = await this.transaction("readonly", (store, set, guard) => {
      const result = []; let bytes = 30;
      const request = store.openCursor();
      request.onsuccess = guard(() => {
        const cursor = request.result;
        if (!cursor) { set(result); return; }
        const value = publicRecord(cursor.value);
        result.push(value); bytes += byteLength(JSON.stringify(value)) + 1;
        requireValue(result.length <= MAX_ARCHIVE_RECORDS && bytes <= MAX_ARCHIVE_BYTES,
          "Memory export exceeds 5 MiB or 10,000 records. Nothing was deleted.");
        cursor.continue();
      });
    });
    return validateMemoryArchive({ version: MEMORY_VERSION, records });
  }
  async importData(data) {
    // Validate the entire archive before opening a write transaction.
    const archive = validateMemoryArchive(data);
    return this.transaction("readwrite", (store, set, guard) => {
      let imported = 0; set(0);
      for (const record of archive.records) {
        const request = store.get(record.id);
        request.onsuccess = guard(() => {
          const previous = request.result;
          requireValue(!previous || previous.kind === record.kind, "Imported ID belongs to a different memory kind.");
          if (!previous || record.updatedAt > previous.updatedAt) {
            // A backup's flags do not grant permission to disclose its text.
            store.put(storedRecord({ ...record, searchable: false, exportable: false })); set(++imported);
          }
        });
      }
    });
  }
  async recall(question, options = {}) {
    const terms = memoryTerms(question).slice(0, 12);
    const records = await this.transaction("readonly", (store, set, guard) => {
      const candidates = new Map(); set(candidates);
      for (const term of terms) {
        let fetched = 0;
        const request = store.index("terms").openCursor(this.keyRange.only(term), "prev");
        request.onsuccess = guard(() => {
          const cursor = request.result;
          if (!cursor || fetched >= 50 || candidates.size >= 200) return;
          candidates.set(cursor.primaryKey, publicRecord(cursor.value)); fetched++;
          if (fetched < 50 && candidates.size < 200) cursor.continue();
        });
      }
      if (asksForMemory(question)) {
        let fetched = 0;
        const request = store.index("updatedAt").openCursor(null, "prev");
        request.onsuccess = guard(() => {
          const cursor = request.result;
          if (!cursor || fetched >= 50 || candidates.size >= 200) return;
          candidates.set(cursor.primaryKey, publicRecord(cursor.value)); fetched++;
          if (fetched < 50 && candidates.size < 200) cursor.continue();
        });
      }
    });
    return selectRelevantMemories(question, [...records.values()], options);
  }
}
