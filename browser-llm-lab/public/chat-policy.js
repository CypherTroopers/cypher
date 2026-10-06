// Deterministic keyword routing, not an LLM judgment or a complete privacy detector.
// Auto can miss current topics or overmatch terminology. Off always keeps local
// chat local; explicit Research bypasses task exclusions but not unsafe queries.
// Context contributes only public product terms, never raw history or note text.
const encoder = new TextEncoder();
const clean = value => typeof value === "string"
  ? value.normalize("NFKC").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/gu, " ").trim() : "";

export function detectLanguage(text, requested = "auto") {
  if (requested === "ja" || requested === "en") return requested;
  return /[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]/u.test(String(text || "")) ? "ja" : "en";
}

export function limitSearchQuery(text) {
  let result = "", length = 0, bytes = 0;
  for (const character of clean(text)) {
    const size = encoder.encode(character).length;
    if (length + character.length > 400 || bytes + size > 1200) break;
    result += character; length += character.length; bytes += size;
  }
  return result.trim();
}

// These are recognizable disclosures, not a promise to detect all sensitive data.
export function isSensitiveQuery(value) {
  const text = clean(value);
  return [
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
    /\b(?:sk-(?:proj-)?[a-z0-9_-]{8,}|gh[pousr]_[a-z0-9]{8,}|AKIA[A-Z0-9]{16}|Bearer\s+\S{6,})\b/i,
    /(?:\b(?:password|passwd|passphrase|api[ _-]?(?:key|token)|(?:access[ _-]?)?token|secret(?:[ _-]?key)?|private[ _-]?key|(?:seed|recovery)[ _-]?phrase)\b|パスワード|暗証番号|秘密鍵|トークン|APIキー|シードフレーズ)\s*(?:[=:：]|\bis\b|は)\s*\S+/i,
    /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/i,
    /\b(?:my|our)\s+(?:password|email|address|phone\s+number|secret|private\s+key)\b/i,
    /私の(?:パスワード|メール|住所|電話番号|秘密鍵)|自宅(?:の|は|住所)|メールアドレス|電話番号/u,
    /\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b|\[::1\]/,
    /https?:\/\/[^\s/]+:[^\s/]+@|\b[\w.-]+\.(?:local|internal|lan)\b/i,
    /〒\s*\d{3}[- ]?\d{4}|\b0[789]0[- ]?\d{4}[- ]?\d{4}\b/,
    /(?:東京都|北海道|大阪府|京都府|[\p{Script=Han}]{2,4}県)[^\n]{0,35}(?:丁目|番地|\d{1,4}[-−]\d{1,4})/u,
    /\b\d{1,5}\s+(?:[\p{L}.'-]+\s+){0,5}(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b/iu,
    /\b(?:\d{4}[ -]){3}\d{4}\b/,
  ].some(pattern => pattern.test(text));
}

// Narrow allowlist: unknown names are deliberately not recovered from private context.
const SUBJECT_PATTERNS = [
  /\b(?:Apple|Google|Microsoft|Samsung|NVIDIA|AMD|Intel|OpenAI|Anthropic)\b/gi,
  /(?:\bDAIKIN\b|ダイキン)(?:\s*(?:エアコン|空気清浄機|air\s*conditioner))?/gi,
  /\b(?:AN|S|F|MCK|MC)\d{2,4}[A-Z]{2,6}(?:[-/][A-Z0-9]{1,5})?\b|うるさら\s*X|\brisora\b/gi,
  /\b(?:iPhone|iPad)(?:\s*\d{1,2})?(?:\s*(?:Pro\s*Max|Pro|Plus|mini|Air))?\b/gi,
  /\bMacBook(?:\s*(?:Pro|Air))?(?:\s*\d{1,2}(?:\s*inch)?)?(?:\s+M[1-9](?:\s*(?:Pro|Max|Ultra))?)?\b/gi,
  /\b(?:Mac\s*mini|Mac\s*Studio|iMac)(?:\s+M[1-9](?:\s*(?:Pro|Max|Ultra))?)?\b/gi,
  /\b(?:Pixel\s*\d{1,2}(?:\s*(?:Pro\s*XL|Pro|XL|a))?|Galaxy\s*(?:S\d{1,2}(?:\s*(?:Ultra|Plus|FE))?|Z\s*(?:Fold|Flip)\s*\d{1,2}))\b/gi,
  /\b(?:RTX\s*\d{3,4}(?:\s*(?:Ti|SUPER))?|Radeon\s*(?:RX\s*)?\d{3,4}(?:\s*(?:XT|XTX))?|Ryzen\s*[3579](?:\s*\d{4}(?:X3D|X)?)?|Core\s*Ultra\s*[579](?:\s*\d{3}[A-Z]?)?)\b/gi,
  /\b(?:Windows\s*(?:10|11)|macOS(?:\s*(?:Sequoia|Tahoe|Sonoma|Ventura))?|iOS\s*\d{1,2}|iPadOS\s*\d{1,2}|Android\s*\d{1,2})\b/gi,
  /\b(?:OpenClaw|Ollama|LM\s*Studio|llama\.cpp|WebLLM|WebGPU|CUDA|Chrome|Chromium|Firefox|Safari|Edge|Docker|Node\.js|Python)\b/gi,
  /\b(?:Qwen\s*\d(?:\.\d)?(?:[- ]\d{1,3}B)?|Llama\s*\d(?:\.\d)?(?:\s*\d{1,3}B)?|Gemma\s*\d(?:\s*\d{1,3}B)?|DeepSeek(?:[- ](?:R1|V3))?|GPT[- ]\d(?:\.\d)?|Claude(?:\s*(?:Sonnet|Opus|Haiku))?)\b/gi,
];

export function extractSafeSubject(value) {
  const text = clean(value);
  if (!text || isSensitiveQuery(text)) return "";
  const matches = SUBJECT_PATTERNS.flatMap(pattern => [...text.matchAll(pattern)]
    .map(match => ({ text: clean(match[0]), index: match.index })));
  matches.sort((a, b) => a.index - b.index || b.text.length - a.text.length);
  const selected = [];
  for (const match of matches) {
    if (!selected.some(item => item.toLowerCase() === match.text.toLowerCase())) selected.push(match.text);
    if (selected.length === 3) break;
  }
  return limitSearchQuery(selected.join(" ")).slice(0, 120).trim();
}

/** Use the current public topic, then the latest user turn, then an opted-in note. */
export function selectSubject({ question = "", history = [], memories = [] } = {}) {
  const current = extractSafeSubject(question);
  if (current) return current;
  if (Array.isArray(history)) {
    for (let index = history.length - 1; index >= 0; index--) {
      if (history[index]?.role !== "user") continue;
      const subject = extractSafeSubject(history[index].content);
      if (subject) return subject;
      break; // An unclear latest user turn must not revive an unrelated older topic.
    }
  }
  if (Array.isArray(memories)) {
    const approved = memories.filter(note => note?.kind === "note" && note.searchable === true)
      .map((note, index) => ({ note, index, updated: Number.isFinite(Number(note.updatedAt))
        ? Number(note.updatedAt) : Date.parse(note.updatedAt) || 0 }))
      .sort((a, b) => b.updated - a.updated || a.index - b.index);
    for (const { note } of approved) {
      const subject = extractSafeSubject(note.subject || note.text || note.content || note.value);
      if (subject) return subject;
    }
  }
  return "";
}

function unquoted(text) {
  return text.replace(/"[^"\n]*"|“[^”\n]*”|「[^」]*」|『[^』]*』|'[^'\n]*'/g, " ");
}
function localTask(text) {
  const translation = /^(?:(?:please|can you|could you|would you)\s+)?(?:translate|rewrite|paraphrase|proofread)\b/i.test(text) ||
    /翻訳(?:して|してください|できますか|お願い|[。!?？]|$)|(?:英訳|和訳)(?:して|してください)?(?:[。!?？]|$)/u.test(text);
  const creative = /^(?:(?:please|can you|could you|would you)\s+)?(?:write|compose|create|tell me)\s+(?:me\s+)?(?:a|an)\s+(?:story|poem|joke|fiction|song)\b|^brainstorm\b/i.test(text) ||
    /(?:物語|詩|小説|童話|架空の).*(?:書いて|作って|考えて)|創作(?:して|してください)/u.test(text);
  const summary = (/^(?:(?:please|can you|could you|would you)\s+)?summari[sz]e\b/i.test(text) || /要約して|まとめて/u.test(text)) &&
    /(?:following|provided|this\s+(?:text|passage)|^summari[sz]e\s*:|以下|次の文章|この文章|["“「『])/iu.test(text);
  return translation || creative || summary;
}
function personalMemory(text) {
  return /(?:私の|自分の).*(?:機種|端末|名前|好み|設定).*(?:覚えて|覚えています|何だった)|前に(?:話した|伝えた).*(?:覚えて|何)/u.test(text) ||
    /\b(?:remember|recall)\b.*\b(?:my|me|our|i)\b|\b(?:what|which)\b.*\bmy\s+(?:(?:current|latest|old|previous)\s+)?(?:device|laptop|phone|name|preferences|settings)\b/i.test(text);
}
const FRESH = /最新|現在|今(?:使える|利用できる|買える|時点|週|月|年|の)|今日|本日|最近|直近|今年|来年|新機能|アップデート|更新|発売|発表|\b(?:latest|current|today|now|recent|recently|upcoming|release|released|launch|launched|update|updates)\b|\b(?:this|next)\s+(?:week|month|year)\b|\bnew\s+(?:version|model|feature|information)\b/iu;
const VOLATILE = /価格|値段|料金|在庫|天気|ニュース|営業時間|運行|株価|為替|大統領|社長|\b(?:price|prices|pricing|cost|news|weather|availability|schedule|ceo|president)\b|exchange\s+rate/iu;
const LOOKUP = /(?:ネット|ウェブ|Web|インターネット)(?:で|を).*(?:検索|調べ)|検索して|調べて|公式(?:サイト|情報).*(?:調べ|探し)|\b(?:search\s+(?:the\s+)?web|look\s+up|google\s+(?:it|this)|find\s+(?:online|official))\b/iu;
const COMPATIBLE = /対応|互換|サポート|使える|動く|動作|必要スペック|\b(?:compatible|compatibility|supported|supports|requirements|specifications|specs)\b|\b(?:work|works|run|runs|install)\s+(?:on|with)\b/iu;
const FOLLOW_UP = /その|それ|これ|あれ|さっきの|この(?:機種|製品|モデル|端末|ソフト|アプリ|ブラウザ)|\b(?:it|its|that|those|these|this\s+(?:one|device|model|product|app)|the\s+same)\b/iu;
const NO_SUBJECT = /^(?:(?:今|現在|最新|価格|値段|料金|更新|バージョン|互換性|対応状況|使える|利用できる|買える|動く|動作)(?:の|は|を|が|って|どう|ですか|教えて|調べて|ください|情報|状況|[\s。!?？])*)+$/u;

function followupQuery(subject, question, language, now) {
  const ja = language === "ja", facets = [];
  if (/価格|値段|料金|\b(?:price|prices|pricing|cost)\b/iu.test(question)) facets.push(ja ? "価格" : "price");
  if (/ニュース|\bnews\b/iu.test(question)) facets.push(ja ? "ニュース" : "news");
  if (COMPATIBLE.test(question)) facets.push(ja ? "対応 互換性" : "compatibility support");
  if (/発売|\brelease\b|\blaunch\b/iu.test(question)) facets.push(ja ? "発売日" : "release date");
  if (/更新|バージョン|\b(?:update|updates|version)\b/iu.test(question)) facets.push(ja ? "最新版 更新情報" : "latest version updates");
  if (!facets.length) facets.push(ja ? "最新情報" : "latest information");
  else if (FRESH.test(question)) facets.unshift(ja ? "最新" : "latest");
  const year = [...question.matchAll(/(?:20|21)\d{2}/g)].map(match => Number(match[0])).find(year => year >= now.getUTCFullYear());
  return limitSearchQuery([subject, ...facets, year || ""].filter(Boolean).join(" "));
}

/**
 * Stable reason codes support UI labels. `blocked` is safe, localized text;
 * it never repeats the private material which caused the block.
 */
export function planSearch({ question = "", mode = "local", policy = "auto", history = [], memories = [],
  customQuery = "", timeRange = "", now = new Date(), language = "auto" } = {}) {
  const text = clean(question), custom = clean(customQuery);
  const result = { search: false, query: "", reason: "no-search-needed", language: detectLanguage(text || custom, language),
    timeRange: ["", "day", "month", "year"].includes(timeRange) ? timeRange : "" };
  const blocked = reason => ({ ...result, reason, blocked: result.language === "ja"
    ? reason === "missing-subject" ? "検索する製品や話題を具体的に教えてください。" : "個人情報や認証情報を含む可能性があります。公開してよい検索語だけを別に指定してください。"
    : reason === "missing-subject" ? "Which product or topic should I search for?" : "This may contain personal information or credentials. Provide separate, public search terms." });
  if (mode === "agent") return { ...result, reason: "agent-managed" };
  if (mode !== "web" && policy === "off") return { ...result, reason: "search-off" };
  if (!text && !custom) return { ...result, reason: "empty-question" };
  let reason;
  if (mode === "web") reason = "explicit-web";
  else if (policy === "always") reason = "always-search";
  else {
    if (personalMemory(text)) return { ...result, reason: "personal-memory" };
    if (localTask(text)) return { ...result, reason: "local-task" };
    const publicText = unquoted(text), subject = extractSafeSubject(publicText);
    const year = now instanceof Date && Number.isFinite(now.getTime()) ? now.getUTCFullYear() : Infinity;
    if (LOOKUP.test(publicText)) reason = "explicit-search";
    else if (COMPATIBLE.test(publicText) && (subject || FOLLOW_UP.test(publicText))) reason = "compatibility";
    else if (FRESH.test(publicText)) reason = "fresh-information";
    else if (VOLATILE.test(publicText)) reason = "changing-information";
    else if ([...publicText.matchAll(/(?:20|21)\d{2}/g)].some(match => Number(match[0]) >= year)) reason = "current-year";
    else return result;
  }
  // A safe custom query replaces the entire question for external search.
  const rawQuery = custom || text;
  if (isSensitiveQuery(rawQuery)) return blocked("unsafe-query");
  let query = rawQuery;
  if (!custom && !extractSafeSubject(text) && (FOLLOW_UP.test(unquoted(text)) || NO_SUBJECT.test(text) ||
    /^(?:and\s+)?(?:what(?:'s| is| are)|tell me|find|look up)?\s*(?:(?:the|latest|current|new|price|prices|version|updates|compatibility|status)\s*)+[!?.,]*$/i.test(text))) {
    const subject = selectSubject({ history, memories });
    if (!subject) return blocked("missing-subject");
    query = followupQuery(subject, text, result.language, now instanceof Date ? now : new Date(NaN));
  }
  query = limitSearchQuery(query);
  return query ? { ...result, search: true, query, reason } : { ...result, reason: "empty-question" };
}
