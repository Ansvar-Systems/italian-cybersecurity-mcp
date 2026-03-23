/**
 * ACN ingestion crawler — scrapes acn.gov.it (including CSIRT Italia) to
 * populate the SQLite database with cybersecurity guidance, advisories,
 * publications, and framework metadata.
 *
 * Data sources:
 *   1. CSIRT Italia RSS feed — security alerts and bulletins
 *      https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192
 *   2. CSIRT Italia alert & bulletin listing pages
 *      https://www.acn.gov.it/portale/csirt-italia/alert-e-bollettini
 *   3. CSIRT Italia publications listing
 *      https://www.acn.gov.it/portale/en/csirt-italia/pubblicazioni
 *   4. ACN NIS guidelines and determinations
 *      https://www.acn.gov.it/portale/en/nis/modalita-specifiche-base
 *   5. ACN document library (PDF guidelines)
 *      https://www.acn.gov.it/portale/documents/d/guest/...
 *
 * Usage:
 *   npx tsx scripts/ingest-acn.ts
 *   npx tsx scripts/ingest-acn.ts --resume      # skip already-ingested references
 *   npx tsx scripts/ingest-acn.ts --dry-run     # parse only, do not write to DB
 *   npx tsx scripts/ingest-acn.ts --force       # delete DB and rebuild from scratch
 *   npx tsx scripts/ingest-acn.ts --max-pages 5 # limit listing pages per source
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import * as cheerio from "cheerio";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["ACN_DB_PATH"] ?? "data/acn.db";

/** Minimum delay between HTTP requests (ms). */
const RATE_LIMIT_MS = 1500;

/** Maximum retries per request on transient failure. */
const MAX_RETRIES = 3;

/** Back-off base for retries (ms). Actual delay = BASE * 2^attempt. */
const RETRY_BACKOFF_BASE_MS = 2000;

/** Default cap on listing pages crawled per source category. */
const DEFAULT_MAX_PAGES = 200;

/** Request timeout (ms). */
const REQUEST_TIMEOUT_MS = 30_000;

const ACN_BASE = "https://www.acn.gov.it";
const CSIRT_RSS_URL = `${ACN_BASE}/portale/feedrss/-/journal/rss/20119/723192`;
const CSIRT_ALERTS_URL = `${ACN_BASE}/portale/csirt-italia/alert-e-bollettini`;
const CSIRT_PUBLICATIONS_URL = `${ACN_BASE}/portale/en/csirt-italia/pubblicazioni`;

const USER_AGENT =
  "AnsvarACNCrawler/1.0 (+https://github.com/Ansvar-Systems/italian-cybersecurity-mcp)";

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const FLAG_RESUME = args.includes("--resume");
const FLAG_DRY_RUN = args.includes("--dry-run");
const FLAG_FORCE = args.includes("--force");

function flagValue(name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

const MAX_PAGES = Number(flagValue("--max-pages") || DEFAULT_MAX_PAGES);

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

function warn(msg: string): void {
  const ts = new Date().toISOString();
  console.warn(`[${ts}] WARN: ${msg}`);
}

function logError(msg: string): void {
  const ts = new Date().toISOString();
  console.error(`[${ts}] ERROR: ${msg}`);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

async function rateLimit(): Promise<void> {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchPage(url: string, attempt = 0): Promise<string> {
  await rateLimit();
  log(`  GET ${url}`);

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const res = await fetch(url, {
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Accept-Language": "it-IT,it;q=0.9,en;q=0.5",
      },
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timer);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.text();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (attempt < MAX_RETRIES) {
      const backoff = RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt);
      warn(`Request failed (${msg}), retrying in ${backoff}ms (attempt ${attempt + 1}/${MAX_RETRIES})`);
      await sleep(backoff);
      return fetchPage(url, attempt + 1);
    }
    throw new Error(`Failed to fetch ${url} after ${MAX_RETRIES} retries: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function openDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    log(`Created directory: ${dir}`);
  }

  if (FLAG_FORCE && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  log(`Database ready at ${DB_PATH}`);
  return db;
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

interface ListingEntry {
  /** Absolute URL to the detail page. */
  url: string;
  /** Reference ID (e.g. AL11/260320/CSIRT-ITA). */
  reference: string;
  /** Title text from the listing. */
  title: string;
  /** Date string (YYYY-MM-DD) if available from listing. */
  date: string | null;
  /** Severity level if available from listing. */
  severity: string | null;
  /** Entry type: "alert" or "bollettino". */
  entryType: string | null;
}

interface ParsedAdvisory {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null; // JSON array
  summary: string | null;
  full_text: string;
  cve_references: string | null; // JSON array
}

interface ParsedGuidance {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string | null;
  full_text: string;
  topics: string | null; // JSON array
  status: string;
}

// ---------------------------------------------------------------------------
// Date parsing
// ---------------------------------------------------------------------------

const ITALIAN_MONTHS: Record<string, string> = {
  gennaio: "01",
  febbraio: "02",
  marzo: "03",
  aprile: "04",
  maggio: "05",
  giugno: "06",
  luglio: "07",
  agosto: "08",
  settembre: "09",
  ottobre: "10",
  novembre: "11",
  dicembre: "12",
};

/**
 * Parse an Italian date string like "20 marzo 2026" or "5 febbraio 2025"
 * into ISO YYYY-MM-DD format.
 */
function parseItalianDate(raw: string): string | null {
  if (!raw) return null;
  const clean = raw.trim().toLowerCase().replace(/\s+/g, " ");

  // Try "DD monthName YYYY" pattern
  const match = clean.match(/(\d{1,2})\s+(\S+)\s+(\d{4})/);
  if (match) {
    const day = match[1]!.padStart(2, "0");
    const monthStr = match[2]!;
    const year = match[3]!;
    const month = ITALIAN_MONTHS[monthStr];
    if (month) return `${year}-${month}-${day}`;
  }

  // Try ISO format already
  const isoMatch = clean.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (isoMatch) return isoMatch[0];

  // Try "DD/MM/YYYY" or "DD/MM/YY"
  const slashMatch = clean.match(/(\d{2})\/(\d{2})\/(\d{2,4})/);
  if (slashMatch) {
    let year = slashMatch[3]!;
    if (year.length === 2) {
      year = Number(year) >= 70 ? `19${year}` : `20${year}`;
    }
    return `${year}-${slashMatch[2]}-${slashMatch[1]}`;
  }

  return null;
}

/**
 * Parse CSIRT listing dates in the format "DD/MM/YY HH:MM" to YYYY-MM-DD.
 */
function parseCsirtListingDate(raw: string): string | null {
  if (!raw) return null;
  const match = raw.trim().match(/(\d{2})\/(\d{2})\/(\d{2})\s/);
  if (!match) return null;
  const year = Number(match[3]!) >= 70 ? `19${match[3]}` : `20${match[3]}`;
  return `${year}-${match[2]}-${match[1]}`;
}

/**
 * Parse an RFC 2822 date from the RSS feed (e.g. "Fri, 20 Mar 2026 16:00:39 GMT")
 * into YYYY-MM-DD.
 */
function parseRssDate(raw: string): string | null {
  if (!raw) return null;
  try {
    const d = new Date(raw);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Topic extraction
// ---------------------------------------------------------------------------

/**
 * Extract topic tags from Italian cybersecurity text by matching known keywords.
 */
function extractTopics(text: string): string[] {
  const lower = text.toLowerCase();
  const topics: string[] = [];
  const topicPatterns: [string, string][] = [
    ["ransomware", "ransomware"],
    ["riscatto", "ransomware"],
    ["phishing", "phishing"],
    ["malware", "malware"],
    ["emotet", "malware"],
    ["trojan", "malware"],
    ["vulnerabilit", "vulnerabilita"],
    ["autenticazione", "autenticazione"],
    ["crittografia", "crittografia"],
    ["cifratura", "crittografia"],
    ["active directory", "active-directory"],
    ["vpn", "vpn"],
    ["firewall", "firewall"],
    ["cloud", "cloud"],
    ["nis\\s?2", "NIS2"],
    ["nis2", "NIS2"],
    ["gdpr", "GDPR"],
    ["infrastruttur.{1,5}critic", "infrastrutture-critiche"],
    ["pa\\b", "PA"],
    ["pubblica amministrazione", "PA"],
    ["scada", "sistemi-industriali"],
    ["ics", "sistemi-industriali"],
    ["ot\\b", "sistemi-industriali"],
    ["supply chain", "supply-chain"],
    ["catena di fornitura", "supply-chain"],
    ["pnrr", "PNRR"],
    ["zero-day", "zero-day"],
    ["0-day", "zero-day"],
    ["denial of service", "DoS"],
    ["dos\\b", "DoS"],
    ["ddos", "DDoS"],
    ["esecuzione di codice", "RCE"],
    ["remote code execution", "RCE"],
    ["privilege escalation", "privilege-escalation"],
    ["elevazione di privil", "privilege-escalation"],
    ["sql injection", "injection"],
    ["cross-site scripting", "XSS"],
    ["xss", "XSS"],
    ["apt\\b", "APT"],
    ["spear.?phishing", "spear-phishing"],
    ["intelligenza artificiale", "AI"],
    ["machine learning", "AI"],
    ["post-quantic", "post-quantum"],
    ["quantum", "post-quantum"],
    ["backup", "backup"],
    ["incident.{1,10}response", "incident-response"],
    ["risposta agli incidenti", "incident-response"],
    ["csirt", "CSIRT"],
    ["perimetro.{1,15}sicurezza", "perimetro-sicurezza"],
    ["framework nazionale", "framework-nazionale"],
    ["misure minime", "misure-minime"],
    ["pec\\b", "PEC"],
    ["spid\\b", "SPID"],
    ["cie\\b", "CIE"],
    ["sanit", "sanita"],
    ["energi", "energia"],
    ["trasport", "trasporti"],
    ["telecomunicazion", "telecomunicazioni"],
    ["5g", "5G"],
    ["iot", "IoT"],
    ["log4j", "log4j"],
    ["aggiornament", "patch-management"],
    ["patch", "patch-management"],
  ];

  const seen = new Set<string>();
  for (const [pattern, topic] of topicPatterns) {
    if (!seen.has(topic) && new RegExp(pattern, "i").test(lower)) {
      seen.add(topic);
      topics.push(topic);
    }
  }

  return topics;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.substring(0, maxLen - 3) + "...";
}

/**
 * Normalise a CSIRT-ITA reference code. The website uses formats like
 * "AL11/260320/CSIRT-ITA" and URL slugs — we keep the compact code form.
 */
function normaliseReference(raw: string): string {
  return raw.trim().replace(/\s+/g, "");
}

// ---------------------------------------------------------------------------
// RSS feed parser
// ---------------------------------------------------------------------------

interface RssItem {
  title: string;
  link: string;
  pubDate: string | null;
  description: string;
  guid: string;
}

function parseRssFeed(xml: string): RssItem[] {
  const $ = cheerio.load(xml, { xmlMode: true });
  const items: RssItem[] = [];

  $("item").each((_i, el) => {
    const title = $(el).find("title").text().trim();
    const link = $(el).find("link").text().trim();
    const pubDate = $(el).find("pubDate").text().trim() || null;
    const description = $(el).find("description").text().trim();
    const guid = $(el).find("guid").text().trim();

    if (title && link) {
      items.push({ title, link, pubDate, description, guid });
    }
  });

  return items;
}

// ---------------------------------------------------------------------------
// CSIRT alert & bulletin listing page parser
// ---------------------------------------------------------------------------

/**
 * Parse the CSIRT Italia alert & bollettini listing page.
 *
 * The listing page (Liferay-based) renders entries with:
 *   - Reference codes like "AL11/260320/CSIRT-ITA" or "BL01/260319/CSIRT-ITA"
 *   - Links in the format /portale/web/guest/-/[slug]  or  /portale/w/[slug]
 *   - Severity badges (Critico, Alto, Medio, Basso)
 *   - Date stamps in "DD/MM/YY HH:MM" format
 *   - Type labels (Alert, Bollettino)
 */
function parseCsirtAlertListing(
  html: string,
): { entries: ListingEntry[]; hasNextPage: boolean } {
  const $ = cheerio.load(html);
  const entries: ListingEntry[] = [];
  const csirtRefPattern = /([A-Z]{2}\d{2}\/\d{6}\/CSIRT-ITA)/;

  // The page text contains all the structured data. We scan anchor elements
  // linking to detail pages and extract metadata from the surrounding context.
  const bodyText = $("body").text();

  // Extract all reference codes from the page
  const refMatches = bodyText.matchAll(/([A-Z]{2}\d{2}\/\d{6}\/CSIRT-ITA)/g);
  const seenRefs = new Set<string>();

  for (const refMatch of refMatches) {
    const ref = normaliseReference(refMatch[1]!);
    if (seenRefs.has(ref)) continue;
    seenRefs.add(ref);
  }

  // Now find links to detail pages and correlate them with references
  $("a").each((_i, el) => {
    const href = $(el).attr("href");
    if (!href) return;

    // Detail page links contain /portale/web/guest/-/ or /portale/w/
    if (
      !href.includes("/portale/web/guest/-/") &&
      !href.includes("/portale/w/")
    ) {
      return;
    }

    // Skip pagination, search, and admin links
    if (href.includes("?") || href.includes("ricerca")) return;

    const title = $(el).text().trim();
    if (!title || title.length < 10) return;

    // Build absolute URL
    let url: string;
    if (href.startsWith("http")) {
      url = href;
    } else {
      url = `${ACN_BASE}${href.startsWith("/") ? "" : "/"}${href}`;
    }

    // Try to find a CSIRT-ITA reference code near this link
    const parentText = $(el).parent().text() + " " + $(el).parents().eq(2).text();
    const nearbyRef = parentText.match(csirtRefPattern);

    // Generate a reference from the slug if no CSIRT code found
    let reference: string;
    if (nearbyRef) {
      reference = normaliseReference(nearbyRef[1]!);
    } else {
      const slug = href
        .replace(/.*\/(?:web\/guest\/-|w)\//, "")
        .replace(/\/$/, "");
      reference = `CSIRT-ITA-${slug.substring(0, 80).toUpperCase().replace(/[^A-Z0-9]/g, "-")}`;
    }

    // Deduplicate
    if (entries.some((e) => e.reference === reference || e.url === url)) return;

    // Extract severity from nearby text
    let severity: string | null = null;
    const contextText = parentText.toLowerCase();
    if (contextText.includes("critico")) severity = "critical";
    else if (contextText.includes("alto")) severity = "high";
    else if (contextText.includes("medio")) severity = "medium";
    else if (contextText.includes("basso")) severity = "low";

    // Extract date from nearby text
    let date: string | null = null;
    const dateMatch = parentText.match(/(\d{2}\/\d{2}\/\d{2})\s+\d{2}:\d{2}/);
    if (dateMatch) {
      date = parseCsirtListingDate(dateMatch[0]!);
    }

    // Determine type (Alert vs Bollettino)
    let entryType: string | null = null;
    if (reference.startsWith("AL")) entryType = "alert";
    else if (reference.startsWith("BL")) entryType = "bollettino";
    else if (contextText.includes("alert")) entryType = "alert";
    else if (contextText.includes("bollettino")) entryType = "bollettino";

    entries.push({ url, reference, title, date, severity, entryType });
  });

  // Pagination detection: look for "Pagina successiva" or page number links
  let hasNextPage = false;
  $("a").each((_i, el) => {
    const text = $(el).text().trim().toLowerCase();
    if (
      text.includes("pagina successiva") ||
      text.includes("successiv") ||
      text === ">" ||
      text === ">>" ||
      text === "\u00bb"
    ) {
      hasNextPage = true;
    }
  });

  return { entries, hasNextPage };
}

// ---------------------------------------------------------------------------
// CSIRT publications listing parser
// ---------------------------------------------------------------------------

function parseCsirtPublicationsListing(
  html: string,
): { entries: ListingEntry[]; hasNextPage: boolean } {
  const $ = cheerio.load(html);
  const entries: ListingEntry[] = [];
  const csirtRefPattern = /([A-Z]{2}\d{2}\/\d{6}\/CSIRT-ITA)/;

  $("a").each((_i, el) => {
    const href = $(el).attr("href");
    if (!href) return;

    if (
      !href.includes("/portale/web/guest/-/") &&
      !href.includes("/portale/w/")
    ) {
      return;
    }

    if (href.includes("?") || href.includes("ricerca")) return;

    const title = $(el).text().trim();
    if (!title || title.length < 10) return;

    let url: string;
    if (href.startsWith("http")) {
      url = href;
    } else {
      url = `${ACN_BASE}${href.startsWith("/") ? "" : "/"}${href}`;
    }

    const parentText = $(el).parent().text() + " " + $(el).parents().eq(2).text();
    const nearbyRef = parentText.match(csirtRefPattern);

    let reference: string;
    if (nearbyRef) {
      reference = normaliseReference(nearbyRef[1]!);
    } else {
      const slug = href
        .replace(/.*\/(?:web\/guest\/-|w)\//, "")
        .replace(/\/$/, "");
      reference = `ACN-PUB-${slug.substring(0, 80).toUpperCase().replace(/[^A-Z0-9]/g, "-")}`;
    }

    if (entries.some((e) => e.reference === reference || e.url === url)) return;

    let date: string | null = null;
    const dateMatch = parentText.match(/(\d{2}\/\d{2}\/\d{2})\s+(?:ore\s+)?\d{2}:\d{2}/);
    if (dateMatch) {
      date = parseCsirtListingDate(dateMatch[0]!);
    }

    entries.push({
      url,
      reference,
      title,
      date,
      severity: null,
      entryType: "publication",
    });
  });

  let hasNextPage = false;
  $("a").each((_i, el) => {
    const text = $(el).text().trim().toLowerCase();
    if (
      text.includes("pagina successiva") ||
      text.includes("successiv") ||
      text === ">" ||
      text === ">>" ||
      text === "\u00bb"
    ) {
      hasNextPage = true;
    }
  });

  return { entries, hasNextPage };
}

// ---------------------------------------------------------------------------
// Detail page parser — advisories (alerts & bulletins)
// ---------------------------------------------------------------------------

/**
 * Parse a CSIRT Italia advisory detail page.
 *
 * Advisory pages are Liferay-rendered with these sections:
 *   - Sintesi (summary)
 *   - Dettagli e potenziali impatti (details)
 *   - Tipologia (attack type)
 *   - Prodotti e versioni affette (affected products)
 *   - Azioni di mitigazione (mitigation)
 *   - CVE table (CVE references)
 *   - Impatto sistemico badge (systemic impact / severity)
 *
 * Because the page is partially JS-rendered (Liferay + React), the static
 * HTML may contain the content in JSON configuration blocks or in plain text
 * sections. We extract from whatever is available.
 */
function parseAdvisoryDetail(
  html: string,
  reference: string,
  listingSeverity: string | null,
): ParsedAdvisory {
  const $ = cheerio.load(html);

  // Extract title
  const title =
    $("h1").first().text().trim() ||
    $("h2").first().text().trim() ||
    $("title").text().trim().replace(/ - ACN$/, "").replace(/ \| .*$/, "") ||
    reference;

  // Full page text for extraction
  const bodyText = $("body").text();

  // Extract date — look for patterns in the page text
  let date: string | null = null;
  const datePatterns = [
    // "DD/MM/YY ore HH:MM" format from CSIRT pages
    /(?:Data\s+(?:di\s+)?(?:aggiornamento|apertura|pubblicazione))[:\s]*(\d{2}\/\d{2}\/\d{2})\s/i,
    // Italian date format
    /(\d{1,2}\s+(?:gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre)\s+\d{4})/i,
    // DD/MM/YYYY
    /(\d{2}\/\d{2}\/\d{4})/,
    // DD/MM/YY
    /(\d{2}\/\d{2}\/\d{2})\s+(?:ore\s+)?\d{2}:\d{2}/,
  ];

  for (const pattern of datePatterns) {
    const m = bodyText.match(pattern);
    if (m?.[1]) {
      const candidate = m[1].includes("/")
        ? parseCsirtListingDate(m[1] + " ") ?? parseItalianDate(m[1])
        : parseItalianDate(m[1]);
      if (candidate) {
        date = candidate;
        break;
      }
    }
  }

  // Extract sections by heading text
  const sections: Record<string, string> = {};
  const sectionHeadings = [
    "sintesi",
    "dettagli e potenziali impatti",
    "dettagli",
    "tipologia",
    "prodotti e versioni affette",
    "prodotti affetti",
    "azioni di mitigazione",
    "mitigazione",
    "raccomandazioni",
    "descrizione",
    "riferimenti",
    "impatto",
  ];

  // Try extracting from structured HTML elements
  const mainContent = $("main, article, .content, .journal-content-article, #content").first();
  const contentRoot = mainContent.length ? mainContent : $("body");

  contentRoot.find("h2, h3, h4, strong, b").each((_i, el) => {
    const heading = $(el).text().trim().toLowerCase();
    for (const sh of sectionHeadings) {
      if (heading.includes(sh)) {
        let sectionText = "";
        let sibling = $(el).next();
        while (sibling.length && !sibling.is("h2, h3, h4")) {
          const t = sibling.text().trim();
          if (t) sectionText += t + "\n";
          sibling = sibling.next();
        }
        if (sectionText) {
          sections[sh] = sectionText.trim();
        }
        break;
      }
    }
  });

  // Build full text from paragraphs
  const paragraphs: string[] = [];
  contentRoot.find("p, li").each((_i, el) => {
    const text = $(el).text().trim();
    if (text.length > 5) {
      paragraphs.push(text);
    }
  });

  // If paragraphs are sparse (JS-rendered page), fall back to full body text
  // cleaned of navigation/boilerplate
  let fullText: string;
  if (paragraphs.length > 3) {
    fullText = paragraphs.join("\n\n");
  } else {
    // Strip common boilerplate from body text
    fullText = bodyText
      .replace(/\s+/g, " ")
      .replace(/.*?(?=(?:Sintesi|Dettagli|Alert|Bollettino))/i, "")
      .replace(/(?:Condividi|Facebook|Twitter|LinkedIn|WhatsApp).*$/i, "")
      .trim();
    if (fullText.length < 50) {
      fullText = bodyText.replace(/\s+/g, " ").trim();
    }
  }

  // Extract CVE references
  const cveMatches = fullText.match(/CVE-\d{4}-\d+/g);
  const cves = cveMatches ? [...new Set(cveMatches)] : [];

  // Extract affected products
  let affectedProducts: string[] = [];
  const affectedSection =
    sections["prodotti e versioni affette"] ??
    sections["prodotti affetti"] ??
    "";
  if (affectedSection) {
    affectedProducts = affectedSection
      .split("\n")
      .map((line) => line.replace(/^[-\u2013\u2022*]\s*/, "").trim())
      .filter((line) => line.length > 2);
  }

  // Determine severity
  let severity = listingSeverity;
  if (!severity) {
    const impactText = (
      sections["impatto"] ??
      sections["tipologia"] ??
      bodyText
    ).toLowerCase();

    if (
      impactText.includes("critico") ||
      impactText.includes("critical")
    ) {
      severity = "critical";
    } else if (
      impactText.includes("alto") ||
      impactText.includes("high")
    ) {
      severity = "high";
    } else if (
      impactText.includes("medio") ||
      impactText.includes("medium")
    ) {
      severity = "medium";
    } else if (
      impactText.includes("basso") ||
      impactText.includes("low")
    ) {
      severity = "low";
    }
  }

  // Determine severity from attack type if still not set
  if (!severity) {
    const typeSection = (sections["tipologia"] ?? "").toLowerCase();
    if (
      typeSection.includes("esecuzione di codice") ||
      typeSection.includes("remote code execution") ||
      typeSection.includes("arbitrary code")
    ) {
      severity = "critical";
    } else if (
      typeSection.includes("denial of service") ||
      typeSection.includes("privilege escalation") ||
      typeSection.includes("elevazione di privil")
    ) {
      severity = "high";
    } else if (typeSection.length > 0) {
      severity = "medium";
    }
  }

  // Build summary
  const summary =
    sections["sintesi"] ??
    sections["descrizione"] ??
    (paragraphs.length > 0 ? paragraphs[0] : null) ??
    null;

  return {
    reference,
    title,
    date,
    severity,
    affected_products:
      affectedProducts.length > 0 ? JSON.stringify(affectedProducts) : null,
    summary: summary ? truncate(summary, 1000) : null,
    full_text: fullText || title,
    cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
  };
}

// ---------------------------------------------------------------------------
// Detail page parser — publications & guidance
// ---------------------------------------------------------------------------

function parsePublicationDetail(
  html: string,
  reference: string,
): ParsedGuidance {
  const $ = cheerio.load(html);

  const title =
    $("h1").first().text().trim() ||
    $("title").text().trim().replace(/ - ACN$/, "").replace(/ \| .*$/, "") ||
    reference;

  const bodyText = $("body").text();

  // Extract date
  let date: string | null = null;
  const datePatterns = [
    /(?:Data\s+(?:di\s+)?(?:pubblicazione|apertura))[:\s]*(\d{2}\/\d{2}\/\d{2})\s/i,
    /(\d{1,2}\s+(?:gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre)\s+\d{4})/i,
    /(\d{2}\/\d{2}\/\d{4})/,
    /(\d{2}\/\d{2}\/\d{2})\s+(?:ore\s+)?\d{2}:\d{2}/,
  ];

  for (const pattern of datePatterns) {
    const m = bodyText.match(pattern);
    if (m?.[1]) {
      const candidate = m[1].includes("/")
        ? parseCsirtListingDate(m[1] + " ") ?? parseItalianDate(m[1])
        : parseItalianDate(m[1]);
      if (candidate) {
        date = candidate;
        break;
      }
    }
  }

  // Extract content
  const mainContent = $("main, article, .content, .journal-content-article, #content").first();
  const contentRoot = mainContent.length ? mainContent : $("body");

  const paragraphs: string[] = [];
  contentRoot.find("p, li, blockquote").each((_i, el) => {
    const text = $(el).text().trim();
    if (text.length > 20) {
      paragraphs.push(text);
    }
  });

  const fullText = paragraphs.length > 3
    ? paragraphs.join("\n\n")
    : bodyText.replace(/\s+/g, " ").trim();

  // Determine type and series
  let type = "publication";
  let series = "CSIRT Italia";

  const lowerTitle = title.toLowerCase();
  const lowerText = fullText.toLowerCase();

  if (lowerTitle.includes("operational summary")) {
    type = "operational-summary";
    series = "Operational Summary";
  } else if (lowerTitle.includes("linee guida") || lowerTitle.includes("guideline")) {
    type = "guidance";
    series = "ACN";
  } else if (lowerTitle.includes("framework")) {
    type = "framework";
    series = "ACN";
  } else if (
    lowerTitle.includes("ransomware") ||
    lowerTitle.includes("infostealer") ||
    lowerTitle.includes("minaccia") ||
    lowerTitle.includes("threat")
  ) {
    type = "threat-report";
    series = "CSIRT Italia";
  } else if (lowerTitle.includes("nis")) {
    type = "regulatory";
    series = "NIS";
  } else if (lowerTitle.includes("report") || lowerTitle.includes("relazione")) {
    type = "report";
    series = "ACN";
  } else if (
    lowerText.includes("autenticazione") ||
    lowerText.includes("crittografia") ||
    lowerText.includes("configurazione")
  ) {
    type = "guidance";
    series = "ACN";
  }

  const summary = paragraphs.length > 0 ? truncate(paragraphs[0]!, 1000) : null;
  const topics = extractTopics(fullText + " " + title);

  return {
    reference,
    title,
    title_en: null,
    date,
    type,
    series,
    summary,
    full_text: fullText || title,
    topics: topics.length > 0 ? JSON.stringify(topics) : null,
    status: "current",
  };
}

// ---------------------------------------------------------------------------
// Database write helpers
// ---------------------------------------------------------------------------

function insertAdvisory(db: Database.Database, adv: ParsedAdvisory): boolean {
  try {
    db.prepare(`
      INSERT OR IGNORE INTO advisories
        (reference, title, date, severity, affected_products, summary, full_text, cve_references)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      adv.reference,
      adv.title,
      adv.date,
      adv.severity,
      adv.affected_products,
      adv.summary,
      adv.full_text,
      adv.cve_references,
    );
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`Failed to insert advisory ${adv.reference}: ${msg}`);
    return false;
  }
}

function insertGuidanceRow(db: Database.Database, g: ParsedGuidance): boolean {
  try {
    db.prepare(`
      INSERT OR IGNORE INTO guidance
        (reference, title, title_en, date, type, series, summary, full_text, topics, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      g.reference,
      g.title,
      g.title_en,
      g.date,
      g.type,
      g.series,
      g.summary,
      g.full_text,
      g.topics,
      g.status,
    );
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`Failed to insert guidance ${g.reference}: ${msg}`);
    return false;
  }
}

function insertFramework(
  db: Database.Database,
  id: string,
  name: string,
  nameEn: string | null,
  description: string | null,
  docCount: number,
): boolean {
  try {
    db.prepare(`
      INSERT OR REPLACE INTO frameworks
        (id, name, name_en, description, document_count)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, name, nameEn, description, docCount);
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`Failed to insert framework ${id}: ${msg}`);
    return false;
  }
}

function referenceExists(db: Database.Database, table: string, reference: string): boolean {
  const row = db
    .prepare(`SELECT 1 FROM ${table} WHERE reference = ? LIMIT 1`)
    .get(reference) as { 1: number } | undefined;
  return row !== undefined;
}

// ---------------------------------------------------------------------------
// Static framework and guidance data
// ---------------------------------------------------------------------------

/**
 * Seed the frameworks table with well-known ACN cybersecurity frameworks.
 * These are stable references that rarely change.
 */
function seedFrameworks(db: Database.Database): void {
  log("\n=== Seeding frameworks ===");

  const frameworks = [
    {
      id: "psnc",
      name: "Piano Strategico Nazionale per la Cybersicurezza 2022-2026",
      name_en: "National Cybersecurity Strategic Plan 2022-2026",
      description:
        "Il Piano Strategico Nazionale per la Cybersicurezza definisce gli obiettivi strategici " +
        "dell'Italia in materia di cybersicurezza per il periodo 2022-2026. Articolato in tre aree " +
        "principali: protezione, risposta e sviluppo. Prevede 82 misure concrete.",
      document_count: 1,
    },
    {
      id: "misure-minime",
      name: "Misure Minime di Sicurezza ICT per le Pubbliche Amministrazioni",
      name_en: "Minimum ICT Security Measures for Public Administrations",
      description:
        "Le Misure Minime di Sicurezza ICT definiscono il livello di sicurezza minimo che le " +
        "pubbliche amministrazioni italiane devono garantire ai propri sistemi informatici. " +
        "Definite in tre livelli: minimo, standard e avanzato. Basate sui CIS Controls.",
      document_count: 1,
    },
    {
      id: "framework-nazionale",
      name: "Framework Nazionale per la Cybersecurity e la Data Protection",
      name_en: "National Cybersecurity and Data Protection Framework",
      description:
        "Adattamento italiano del NIST Cybersecurity Framework, integrato con i requisiti del GDPR " +
        "e della Direttiva NIS/NIS2. Organizzato in cinque funzioni (Identificare, Proteggere, " +
        "Rilevare, Rispondere, Ripristinare) con 108 sottocategorie di controllo.",
      document_count: 1,
    },
    {
      id: "nis2-specifiche-base",
      name: "Linee Guida NIS - Specifiche di Base",
      name_en: "NIS Guidelines - Base Specifications",
      description:
        "Determinazione ACN che stabilisce le modalita e le specifiche di base per l'adempimento " +
        "degli obblighi previsti dal decreto NIS. Definisce le misure di sicurezza obbligatorie per " +
        "i soggetti essenziali e importanti.",
      document_count: 4,
    },
    {
      id: "perimetro-sicurezza",
      name: "Perimetro di Sicurezza Nazionale Cibernetica",
      name_en: "National Cybersecurity Perimeter",
      description:
        "Quadro normativo (D.L. 105/2019 e successive modifiche) che definisce il perimetro di " +
        "sicurezza nazionale cibernetica per la protezione delle infrastrutture critiche e dei " +
        "servizi essenziali dello Stato italiano.",
      document_count: 1,
    },
    {
      id: "strategia-cloud",
      name: "Strategia Cloud Italia",
      name_en: "Cloud Italy Strategy",
      description:
        "Strategia per la migrazione dei sistemi informativi della PA verso il cloud. Definisce " +
        "tre classi di dati/servizi (ordinari, critici, strategici) e i criteri di qualificazione " +
        "dei servizi cloud. Include il Polo Strategico Nazionale (PSN).",
      document_count: 1,
    },
    {
      id: "linee-guida-crittografia",
      name: "Linee Guida sulla Crittografia",
      name_en: "Cryptography Guidelines",
      description:
        "Serie di linee guida dell'ACN sulla crittografia, incluse le raccomandazioni per la " +
        "conservazione delle password, funzioni hash, codici di autenticazione dei messaggi, " +
        "confidenzialita dei dati e preparazione alle minacce quantistiche.",
      document_count: 3,
    },
    {
      id: "linee-guida-csirt",
      name: "Linee Guida per la Realizzazione di CSIRT",
      name_en: "Guidelines for Establishing CSIRTs",
      description:
        "Linee guida dell'ACN per la creazione e la gestione di Computer Security Incident " +
        "Response Team, con indicazioni su organizzazione, processi, strumenti e cooperazione.",
      document_count: 1,
    },
  ];

  let inserted = 0;
  for (const f of frameworks) {
    if (insertFramework(db, f.id, f.name, f.name_en, f.description, f.document_count)) {
      inserted++;
    }
  }
  log(`Frameworks: inserted/updated ${inserted}`);
}

/**
 * Seed the guidance table with well-known ACN publications and NIS guidelines
 * that are available as static documents (PDFs) rather than web pages.
 * These are stable, high-value references.
 */
function seedStaticGuidance(db: Database.Database): void {
  log("\n=== Seeding static guidance documents ===");

  const staticGuidance: ParsedGuidance[] = [
    {
      reference: "ACN-PSNC-2022",
      title: "Piano Strategico Nazionale per la Cybersicurezza 2022-2026",
      title_en: "National Cybersecurity Strategic Plan 2022-2026",
      date: "2022-05-25",
      type: "framework",
      series: "PSNC",
      summary:
        "Il Piano Strategico Nazionale per la Cybersicurezza 2022-2026 definisce gli obiettivi e " +
        "le azioni dell'Italia per rafforzare la propria postura di sicurezza cibernetica. Prevede " +
        "82 misure concrete organizzate in tre aree: protezione, risposta e sviluppo.",
      full_text:
        "Il Piano Strategico Nazionale per la Cybersicurezza 2022-2026 e il documento che " +
        "definisce la visione e gli obiettivi strategici dell'Italia in materia di cybersicurezza. " +
        "Adottato dall'Agenzia per la Cybersicurezza Nazionale (ACN). Tre aree strategiche: " +
        "(1) Protezione — rafforzare la resilienza dei sistemi IT/OT della PA e delle " +
        "infrastrutture critiche, completare l'implementazione della Direttiva NIS e NIS2, " +
        "sviluppare capacita di difesa cibernetica. (2) Risposta — potenziare le capacita di " +
        "risposta agli incidenti del CSIRT Italia, sviluppare le capacita di intelligence sulle " +
        "minacce, rafforzare la cooperazione internazionale. (3) Sviluppo — promuovere la " +
        "ricerca e l'innovazione in cybersicurezza, sviluppare competenze e formare esperti, " +
        "sostenere l'industria italiana della cybersicurezza. Il piano prevede un investimento " +
        "complessivo di circa 623 milioni di euro nel periodo 2022-2026, finanziato anche " +
        "attraverso i fondi del Piano Nazionale di Ripresa e Resilienza (PNRR).",
      topics: JSON.stringify(["PA", "infrastrutture-critiche", "PNRR", "NIS2", "CSIRT"]),
      status: "current",
    },
    {
      reference: "ACN-MS-2017",
      title: "Misure Minime di Sicurezza ICT per le Pubbliche Amministrazioni",
      title_en: "Minimum ICT Security Measures for Public Administrations",
      date: "2017-04-17",
      type: "framework",
      series: "MiSE",
      summary:
        "Documento che definisce le misure minime di sicurezza ICT obbligatorie per le pubbliche " +
        "amministrazioni italiane. Articolato in tre livelli (minimo, standard, avanzato) e basato " +
        "sui 20 Controlli CIS. Adottato con Circolare AgID n. 2/2017.",
      full_text:
        "Le Misure Minime di Sicurezza ICT per le Pubbliche Amministrazioni sono state adottate " +
        "con Circolare AgID n. 2/2017 e sono obbligatorie per tutte le PA italiane. Si basano " +
        "sui Critical Security Controls (CIS Controls) e definiscono tre livelli di sicurezza: " +
        "(1) Livello Minimo — il livello che ogni PA deve necessariamente raggiungere. Comprende " +
        "inventario dispositivi, inventario software, protezione da malware, valutazione continua " +
        "delle vulnerabilita, gestione delle configurazioni sicure, protezione dei dati, difese " +
        "perimetrali, capacita di risposta agli incidenti. (2) Livello Standard — il livello che " +
        "la maggior parte delle PA deve raggiungere per una protezione adeguata. Aggiunge " +
        "controlli avanzati di accesso, protezione dei dati sensibili, audit log, sicurezza " +
        "delle reti wireless, addestramento del personale. (3) Livello Avanzato — per le PA " +
        "che gestiscono dati critici o infrastrutture essenziali. Include penetration testing, " +
        "sicurezza avanzata dei sistemi, controllo degli accessi privilegiati, risposta avanzata " +
        "agli incidenti. Il documento e stato aggiornato nel 2020 per allinearlo ai nuovi " +
        "controlli CIS v7.1.",
      topics: JSON.stringify(["PA", "misure-minime", "patch-management", "incident-response"]),
      status: "current",
    },
    {
      reference: "ACN-FN-2022",
      title: "Framework Nazionale per la Cybersecurity e la Data Protection v2.0",
      title_en: "National Cybersecurity and Data Protection Framework v2.0",
      date: "2022-01-01",
      type: "framework",
      series: "ACN",
      summary:
        "Versione 2.0 del Framework Nazionale, adattamento del NIST CSF integrato con GDPR e " +
        "NIS. Organizzato in cinque funzioni (Identificare, Proteggere, Rilevare, Rispondere, " +
        "Ripristinare) con 108 sottocategorie di controllo.",
      full_text:
        "Il Framework Nazionale per la Cybersecurity e la Data Protection v2.0 e uno strumento " +
        "volontario per la gestione del rischio cyber nelle organizzazioni italiane, pubbliche " +
        "e private. E un adattamento del NIST Cybersecurity Framework integrato con i requisiti " +
        "del GDPR, della Direttiva NIS e della Direttiva NIS2. Struttura del Framework: " +
        "(1) Identificare (Identify) — comprendere il contesto organizzativo, la gestione del " +
        "rischio, e i sistemi informativi critici; (2) Proteggere (Protect) — implementare " +
        "salvaguardie per garantire la continuita dei servizi critici; (3) Rilevare (Detect) — " +
        "implementare attivita per identificare il verificarsi di eventi di cybersecurity; " +
        "(4) Rispondere (Respond) — sviluppare e attuare le azioni appropriate in risposta a " +
        "un incidente di cybersecurity; (5) Ripristinare (Recover) — attuare piani per la " +
        "resilienza e ripristinare capacita e servizi compromessi da un incidente. Il Framework " +
        "include anche una dimensione aggiuntiva dedicata alla protezione dei dati personali, " +
        "in linea con i requisiti del GDPR.",
      topics: JSON.stringify(["framework-nazionale", "GDPR", "NIS2"]),
      status: "current",
    },
    {
      reference: "ACN-LN-2023",
      title: "Linee Guida per la sicurezza delle Infrastrutture Critiche",
      title_en: "Security Guidelines for Critical Infrastructure",
      date: "2023-09-01",
      type: "guidance",
      series: "ACN",
      summary:
        "Linee guida dell'ACN per la protezione delle infrastrutture critiche nazionali. " +
        "Coprono la valutazione del rischio, le misure di sicurezza fisiche e logiche, la " +
        "continuita operativa e la notifica degli incidenti per i settori energia, trasporti, " +
        "acqua e telecomunicazioni.",
      full_text:
        "Le linee guida dell'ACN per la sicurezza delle infrastrutture critiche si applicano " +
        "agli Operatori di Servizi Essenziali (OSE) e ai Fornitori di Servizi Digitali (FSD) " +
        "identificati ai sensi del D.Lgs. 65/2018 (NIS). I settori coperti includono energia " +
        "(produzione, trasmissione e distribuzione elettrica; produzione, raffinazione e " +
        "stoccaggio di petrolio e gas), trasporti, acqua potabile, infrastrutture digitali, " +
        "operatori sanitari e banche. Principi fondamentali: (1) Approccio basato sul rischio " +
        "— le misure di sicurezza devono essere proporzionate al rischio reale; " +
        "(2) Sicurezza by design — la sicurezza deve essere integrata fin dalla progettazione " +
        "dei sistemi; (3) Difesa in profondita — utilizzo di molteplici livelli di sicurezza; " +
        "(4) Resilienza — capacita di resistere e recuperare da incidenti. Obblighi di notifica: " +
        "gli incidenti con impatto significativo sulla continuita dei servizi essenziali devono " +
        "essere notificati al CSIRT Italia entro 24 ore.",
      topics: JSON.stringify([
        "infrastrutture-critiche", "NIS2", "incident-response", "energia", "trasporti",
      ]),
      status: "current",
    },
    {
      reference: "ACN-CLOUD-PA-2023",
      title: "Strategia Cloud Italia — Linee Guida per la migrazione al Cloud della PA",
      title_en: "Cloud Italy Strategy — Migration Guidelines for Public Administrations",
      date: "2023-03-01",
      type: "guidance",
      series: "ACN",
      summary:
        "Linee guida per la migrazione dei sistemi informativi delle pubbliche amministrazioni " +
        "italiane verso il cloud. Definisce tre classi di dati/servizi (ordinari, critici, " +
        "strategici) con requisiti di sicurezza differenziati e i criteri per la qualificazione " +
        "dei servizi cloud per la PA.",
      full_text:
        "La Strategia Cloud Italia mira a consolidare i data center della PA e migrarli verso " +
        "infrastrutture cloud sicure e certificate. L'ACN e responsabile della qualificazione " +
        "dei servizi cloud per la Pubblica Amministrazione. Classificazione dei dati e servizi: " +
        "(1) Ordinari — dati che non comportano rischi elevati; possono migrare su cloud " +
        "certificati CSP in ambito UE; (2) Critici — dati che possono comportare rischi per " +
        "l'ordine pubblico, la sicurezza o l'erogazione di servizi essenziali; richiedono " +
        "cloud qualificati ACN; (3) Strategici — dati la cui compromissione potrebbe arrecare " +
        "danni alla sicurezza nazionale; richiedono il Polo Strategico Nazionale (PSN). Il Polo " +
        "Strategico Nazionale e l'infrastruttura cloud sovrana italiana, gestita da un consorzio " +
        "privato con controllo governativo, che ospita i dati strategici della PA italiana.",
      topics: JSON.stringify(["cloud", "PA"]),
      status: "current",
    },
    {
      reference: "ACN-DET-379907-2025",
      title: "Determinazione ACN 379907/2025 — Specifiche di base NIS",
      title_en: "ACN Determination 379907/2025 — NIS Base Specifications",
      date: "2025-04-14",
      type: "regulatory",
      series: "NIS",
      summary:
        "Determinazione dell'ACN che stabilisce le modalita e le specifiche di base per " +
        "l'adempimento degli obblighi previsti dal decreto NIS per i soggetti essenziali " +
        "e importanti. Definisce le misure di sicurezza obbligatorie e i requisiti di " +
        "notifica degli incidenti.",
      full_text:
        "La Determinazione ACN 379907/2025 stabilisce le specifiche di base per l'adempimento " +
        "degli obblighi previsti dagli articoli 23, 24, 25, 29 e 32 del decreto NIS (D.Lgs. " +
        "138/2024). Le misure di sicurezza sono sviluppate in accordo al Framework Nazionale " +
        "per la Cybersecurity e la Data Protection (edizione 2025), organizzate per funzioni, " +
        "categorie, sottocategorie e requisiti. I soggetti importanti devono adottare le misure " +
        "dell'Allegato 1 entro 18 mesi dalla notifica di inclusione nella lista NIS (ottobre " +
        "2026). I soggetti essenziali devono adottare le misure dell'Allegato 2 entro la stessa " +
        "scadenza. Per la notifica degli incidenti, i soggetti importanti seguono l'Allegato 3 " +
        "e i soggetti essenziali l'Allegato 4, con scadenza di adeguamento a 9 mesi dalla " +
        "notifica (gennaio 2026). Le notifiche devono essere inviate al CSIRT Italia.",
      topics: JSON.stringify(["NIS2", "PA", "incident-response", "framework-nazionale"]),
      status: "current",
    },
    {
      reference: "ACN-NIS-GUIDA-LETTURA-2025",
      title: "Linee guida NIS — Specifiche di base: Guida alla lettura",
      title_en: "NIS Guidelines — Base Specifications: Reading Guide",
      date: "2025-09-01",
      type: "guidance",
      series: "NIS",
      summary:
        "Guida alla comprensione e all'interpretazione delle specifiche di base del decreto " +
        "NIS. Fornisce indicazioni operative e concrete per l'attuazione della nuova normativa " +
        "NIS verso una maggiore resilienza digitale.",
      full_text:
        "La guida alla lettura delle Linee guida NIS — Specifiche di base fornisce indicazioni " +
        "per agevolare la comprensione e l'interpretazione delle specifiche di base stabilite " +
        "dalla Determinazione ACN. Il documento supporta i soggetti NIS nell'attuazione " +
        "degli obblighi previsti dal decreto, con un approccio operativo che descrive le " +
        "relazioni tra le fasi del processo di gestione della sicurezza e le misure di " +
        "sicurezza di base. Copre i temi della governance della cybersicurezza, della gestione " +
        "del rischio, della protezione dei sistemi e dei dati, del monitoraggio e rilevamento " +
        "delle minacce, della risposta agli incidenti e del ripristino dei servizi.",
      topics: JSON.stringify(["NIS2", "PA"]),
      status: "current",
    },
    {
      reference: "ACN-NIS-INCIDENTI-2025",
      title: "Linee guida NIS — Definizione del processo di gestione degli incidenti",
      title_en: "NIS Guidelines — Incident Management Process Definition",
      date: "2025-10-01",
      type: "guidance",
      series: "NIS",
      summary:
        "Linee guida per la definizione del processo di gestione degli incidenti di sicurezza " +
        "informatica per i soggetti NIS. Propone un modello per il processo di gestione degli " +
        "incidenti e descrive le relazioni tra le fasi del processo e le misure di sicurezza.",
      full_text:
        "Le linee guida per la definizione del processo di gestione degli incidenti di sicurezza " +
        "informatica supportano i soggetti NIS nell'adempimento degli obblighi di notifica e " +
        "gestione degli incidenti previsti dal decreto. Il documento propone un modello per il " +
        "processo di gestione degli incidenti articolato in fasi: preparazione, rilevamento e " +
        "analisi, contenimento, eradicazione e ripristino, attivita post-incidente. Per ogni " +
        "fase vengono descritte le relazioni con le misure di sicurezza di base definite nella " +
        "Determinazione ACN 379907/2025. Il modello e coerente con le prassi internazionali " +
        "(NIST SP 800-61, ISO/IEC 27035) e con il Framework Nazionale per la Cybersecurity.",
      topics: JSON.stringify(["NIS2", "incident-response", "CSIRT", "framework-nazionale"]),
      status: "current",
    },
    {
      reference: "ACN-CSIRT-GUIDA-2024",
      title: "Linee Guida per la Realizzazione di CSIRT v2.0",
      title_en: "Guidelines for Establishing CSIRTs v2.0",
      date: "2024-06-01",
      type: "guidance",
      series: "ACN",
      summary:
        "Linee guida dell'ACN per la creazione e gestione di CSIRT (Computer Security Incident " +
        "Response Team). Coprono l'organizzazione, i processi, gli strumenti e le modalita di " +
        "cooperazione con il CSIRT Italia.",
      full_text:
        "Le Linee Guida per la Realizzazione di CSIRT v2.0 (giugno 2024) forniscono un " +
        "riferimento per organizzazioni che intendono istituire o potenziare il proprio Computer " +
        "Security Incident Response Team. Un CSIRT e un team organizzato di esperti di " +
        "cybersicurezza il cui obiettivo principale e la gestione degli incidenti cyber e " +
        "l'offerta di servizi per prevenire, mitigare e risolvere gli impatti degli incidenti " +
        "informatici. Il documento copre: definizione della missione e del mandato del CSIRT, " +
        "modelli organizzativi (dedicato, distribuito, ibrido), servizi da erogare (reattivi, " +
        "proattivi, di gestione della qualita della sicurezza), risorse umane e competenze " +
        "necessarie, strumenti e infrastruttura tecnologica, processi di gestione degli " +
        "incidenti, modalita di cooperazione con il CSIRT Italia e con la rete di CSIRT " +
        "nazionali ed europei, metriche e indicatori di performance.",
      topics: JSON.stringify(["CSIRT", "incident-response"]),
      status: "current",
    },
    {
      reference: "ACN-CRITTOGRAFIA-PASSWORD-2024",
      title: "Linee Guida sulla conservazione delle password",
      title_en: "Guidelines on Password Storage",
      date: "2024-01-01",
      type: "guidance",
      series: "Crittografia",
      summary:
        "Linee guida dell'ACN sulle funzioni crittografiche per la conservazione sicura delle " +
        "password. Coprono gli algoritmi raccomandati, le configurazioni minime e le prassi " +
        "da adottare per la protezione delle credenziali.",
      full_text:
        "Le linee guida dell'ACN sulla conservazione delle password forniscono raccomandazioni " +
        "sulle funzioni crittografiche da utilizzare per proteggere le credenziali archiviate. " +
        "Il documento specifica: algoritmi raccomandati per l'hashing delle password (Argon2id, " +
        "bcrypt, scrypt, PBKDF2), parametri minimi di configurazione per ogni algoritmo, " +
        "l'obbligo di utilizzare salt casuali di lunghezza adeguata (almeno 16 byte), " +
        "la necessita di separare la logica di verifica dalla logica di archiviazione, " +
        "le prassi di migrazione da algoritmi obsoleti (MD5, SHA-1 senza salt) verso " +
        "quelli raccomandati, il divieto di archiviare password in chiaro o con cifratura " +
        "reversibile. Queste linee guida si applicano a tutte le organizzazioni che gestiscono " +
        "credenziali di accesso.",
      topics: JSON.stringify(["crittografia", "autenticazione"]),
      status: "current",
    },
    {
      reference: "ACN-CRITTOGRAFIA-HASH-2024",
      title: "Linee Guida sulle funzioni hash e i codici di autenticazione dei messaggi",
      title_en: "Guidelines on Hash Functions and Message Authentication Codes",
      date: "2024-03-01",
      type: "guidance",
      series: "Crittografia",
      summary:
        "Linee guida dell'ACN sulle funzioni hash crittografiche e i codici di autenticazione " +
        "dei messaggi (MAC). Definisce gli algoritmi raccomandati e le lunghezze minime di " +
        "output per garantire l'integrita e l'autenticita dei dati.",
      full_text:
        "Le linee guida sulle funzioni hash e i codici di autenticazione dei messaggi coprono: " +
        "funzioni hash raccomandate (SHA-256, SHA-384, SHA-512, SHA-3), lunghezze minime di " +
        "output (256 bit per applicazioni generali), codici di autenticazione dei messaggi " +
        "(HMAC-SHA-256, HMAC-SHA-384, CMAC-AES), requisiti per l'utilizzo in protocolli di " +
        "comunicazione sicura (TLS 1.2+, IPsec), linee guida per la transizione verso " +
        "algoritmi resistenti alla computazione quantistica. Il documento fa parte della " +
        "serie di linee guida dell'ACN sulla crittografia.",
      topics: JSON.stringify(["crittografia"]),
      status: "current",
    },
    {
      reference: "ACN-CRITTOGRAFIA-CONFIDENZIALITA-2025",
      title: "Linee Guida sulla crittografia per la confidenzialita dei dati",
      title_en: "Guidelines on Cryptography for Data Confidentiality",
      date: "2025-01-01",
      type: "guidance",
      series: "Crittografia",
      summary:
        "Linee guida dell'ACN sulla crittografia dedicate alla confidenzialita dei dati e " +
        "alle tecniche di preparazione alle minacce quantistiche (post-quantum cryptography).",
      full_text:
        "Le linee guida sulla crittografia per la confidenzialita dei dati rappresentano il " +
        "terzo capitolo della serie sulla crittografia dell'ACN. Coprono: algoritmi di " +
        "cifratura simmetrica raccomandati (AES-256-GCM, AES-256-CCM, ChaCha20-Poly1305), " +
        "algoritmi di cifratura asimmetrica (RSA con chiavi >= 3072 bit, ECDSA/ECDH con " +
        "curve >= 256 bit), modalita operative sicure e da evitare (ECB vietata), gestione " +
        "delle chiavi crittografiche (generazione, distribuzione, rotazione, distruzione), " +
        "requisiti per la cifratura dei dati a riposo e in transito, introduzione alla " +
        "crittografia post-quantistica (CRYSTALS-Kyber, CRYSTALS-Dilithium) e strategie " +
        "di migrazione verso algoritmi quantum-resistant.",
      topics: JSON.stringify(["crittografia", "post-quantum"]),
      status: "current",
    },
    {
      reference: "ACN-BANCHE-DATI-CRITICHE",
      title: "Linee Guida per il rafforzamento della protezione delle banche dati critiche",
      title_en: "Guidelines for Strengthening Critical Database Protection",
      date: "2024-06-01",
      type: "guidance",
      series: "ACN",
      summary:
        "Linee guida dell'ACN per il rafforzamento della protezione delle banche dati critiche " +
        "contro il rischio di uso improprio. Coprono il controllo degli accessi, il monitoraggio, " +
        "la cifratura e la segregazione dei dati.",
      full_text:
        "Le linee guida dell'ACN per la protezione delle banche dati critiche forniscono " +
        "indicazioni per ridurre il rischio di accessi non autorizzati e di uso improprio " +
        "dei dati. Le misure raccomandate includono: implementazione del principio del minimo " +
        "privilegio per l'accesso ai database, autenticazione multifattore per gli " +
        "amministratori, monitoraggio e registrazione di tutte le attivita di accesso, " +
        "cifratura dei dati a riposo e in transito, segregazione delle banche dati critiche " +
        "dalla rete generale, procedure di backup e ripristino verificate regolarmente, " +
        "test di penetrazione periodici sui sistemi di gestione dei database, formazione " +
        "del personale con accesso ai dati critici.",
      topics: JSON.stringify(["PA", "crittografia", "autenticazione"]),
      status: "current",
    },
    {
      reference: "ACN-NOTIFICA-INCIDENTI-2024",
      title: "Guida alla notifica degli incidenti al CSIRT Italia",
      title_en: "Guide to Incident Notification to CSIRT Italia",
      date: "2024-01-01",
      type: "guidance",
      series: "ACN",
      summary:
        "Guida operativa dell'ACN per la notifica degli incidenti informatici al CSIRT Italia. " +
        "Descrive i criteri per la classificazione degli incidenti, le tempistiche di notifica " +
        "e le modalita di comunicazione.",
      full_text:
        "La guida alla notifica degli incidenti al CSIRT Italia fornisce indicazioni operative " +
        "per la segnalazione degli incidenti informatici da parte dei soggetti inclusi nel " +
        "Perimetro di Sicurezza Nazionale Cibernetica e dei soggetti NIS. Contenuti: " +
        "definizione di incidente informatico rilevante, criteri di classificazione della " +
        "gravita (scala da 1 a 4), tempistiche di notifica (24 ore per la prima segnalazione, " +
        "72 ore per la notifica completa), informazioni da includere nella notifica (descrizione " +
        "dell'incidente, impatto stimato, misure adottate, indicatori di compromissione), " +
        "canali di comunicazione con il CSIRT Italia, obblighi di aggiornamento successivo.",
      topics: JSON.stringify(["CSIRT", "incident-response", "perimetro-sicurezza"]),
      status: "current",
    },
    {
      reference: "ACN-RESILIENZA-2025",
      title: "Linee guida per il rafforzamento della resilienza e referente per la cybersicurezza",
      title_en: "Guidelines for Resilience Strengthening and Cybersecurity Point of Contact",
      date: "2025-01-01",
      type: "guidance",
      series: "ACN",
      summary:
        "Linee guida articolate in due parti: la prima identifica le misure di sicurezza per " +
        "rafforzare la resilienza, la seconda supporta le entita nell'implementazione con " +
        "modalita raccomandate.",
      full_text:
        "Le linee guida per il rafforzamento della resilienza si rivolgono alle organizzazioni " +
        "soggette alla normativa NIS e al Perimetro di Sicurezza Nazionale Cibernetica. " +
        "Prima parte: misure di sicurezza per la resilienza — governance della cybersicurezza, " +
        "gestione del rischio, protezione degli asset, gestione delle vulnerabilita, " +
        "monitoraggio continuo, gestione degli incidenti, continuita operativa, formazione " +
        "e sensibilizzazione. Seconda parte: implementazione delle misure — il ruolo del " +
        "referente per la cybersicurezza, modalita di valutazione dello stato di sicurezza, " +
        "pianificazione degli interventi, verifica dell'efficacia delle misure adottate. " +
        "Il referente per la cybersicurezza e la figura designata come punto di contatto " +
        "con l'ACN e il CSIRT Italia.",
      topics: JSON.stringify(["NIS2", "incident-response", "perimetro-sicurezza"]),
      status: "current",
    },
  ];

  let inserted = 0;
  for (const g of staticGuidance) {
    if (FLAG_RESUME && referenceExists(db, "guidance", g.reference)) {
      continue;
    }
    if (FLAG_DRY_RUN) {
      log(`  [DRY RUN] Would insert guidance: ${g.reference} — ${g.title}`);
      continue;
    }
    if (insertGuidanceRow(db, g)) {
      inserted++;
    }
  }
  log(`Static guidance: inserted ${inserted} / ${staticGuidance.length}`);
}

// ---------------------------------------------------------------------------
// Crawl orchestration: CSIRT RSS feed
// ---------------------------------------------------------------------------

async function crawlCsirtRss(
  db: Database.Database,
): Promise<{ inserted: number; skipped: number; errors: number }> {
  log("\n=== Crawling: CSIRT Italia RSS feed ===");

  let totalInserted = 0;
  let totalSkipped = 0;
  let totalErrors = 0;

  let rssXml: string;
  try {
    rssXml = await fetchPage(CSIRT_RSS_URL);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logError(`Failed to fetch RSS feed: ${msg}`);
    return { inserted: 0, skipped: 0, errors: 1 };
  }

  const items = parseRssFeed(rssXml);
  log(`RSS feed contains ${items.length} items`);

  for (const item of items) {
    // Generate reference from link or title
    const urlPath = new URL(item.link).pathname;
    const slug = urlPath
      .replace(/.*\/(?:web\/guest\/-|w)\//, "")
      .replace(/\/$/, "");

    // Try to extract a CSIRT-ITA reference from the title or description
    const csirtMatch = (item.title + " " + item.description).match(
      /([A-Z]{2}\d{2}\/\d{6}\/CSIRT-ITA)/,
    );
    const reference = csirtMatch
      ? normaliseReference(csirtMatch[1]!)
      : `CSIRT-ITA-${slug.substring(0, 80).toUpperCase().replace(/[^A-Z0-9]/g, "-")}`;

    // Resume mode: skip if already in DB
    if (FLAG_RESUME && referenceExists(db, "advisories", reference)) {
      totalSkipped++;
      continue;
    }

    if (FLAG_DRY_RUN) {
      log(`  [DRY RUN] Would fetch: ${reference} — ${item.title}`);
      totalSkipped++;
      continue;
    }

    // Fetch the detail page for full content
    let detailHtml: string;
    try {
      detailHtml = await fetchPage(item.link);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`Failed to fetch detail for ${reference}: ${msg}`);
      totalErrors++;
      continue;
    }

    const parsed = parseAdvisoryDetail(detailHtml, reference, null);

    // Use the RSS date if the detail page didn't provide one
    if (!parsed.date && item.pubDate) {
      parsed.date = parseRssDate(item.pubDate);
    }

    // If we still have no full text, use the RSS description
    if (parsed.full_text.length < 50 && item.description.length > 50) {
      parsed.full_text = item.description;
    }

    if (insertAdvisory(db, parsed)) {
      totalInserted++;
      log(`  Inserted advisory: ${reference} — ${parsed.title}`);
    } else {
      totalSkipped++;
    }
  }

  return { inserted: totalInserted, skipped: totalSkipped, errors: totalErrors };
}

// ---------------------------------------------------------------------------
// Crawl orchestration: CSIRT alert & bulletin listing pages
// ---------------------------------------------------------------------------

async function crawlCsirtAlerts(
  db: Database.Database,
): Promise<{ inserted: number; skipped: number; errors: number }> {
  log("\n=== Crawling: CSIRT Italia alerts & bulletins ===");

  let totalInserted = 0;
  let totalSkipped = 0;
  let totalErrors = 0;
  let page = 0;

  while (page < MAX_PAGES) {
    const start = page * 20;
    const listUrl = `${CSIRT_ALERTS_URL}?start=${start}&delta=20`;
    log(`Fetching alert listing page ${page + 1} (start=${start})`);

    let listHtml: string;
    try {
      listHtml = await fetchPage(listUrl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`Failed to fetch listing page ${page + 1}: ${msg}`);
      totalErrors++;
      break;
    }

    const { entries, hasNextPage } = parseCsirtAlertListing(listHtml);

    if (entries.length === 0) {
      log(`No entries found on page ${page + 1}, stopping`);
      break;
    }

    log(`Found ${entries.length} entries on page ${page + 1}`);

    for (const entry of entries) {
      // Resume mode: skip if already in DB
      if (FLAG_RESUME && referenceExists(db, "advisories", entry.reference)) {
        totalSkipped++;
        continue;
      }

      if (FLAG_DRY_RUN) {
        log(`  [DRY RUN] Would fetch: ${entry.reference} — ${entry.title}`);
        totalSkipped++;
        continue;
      }

      // Fetch detail page
      let detailHtml: string;
      try {
        detailHtml = await fetchPage(entry.url);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logError(`Failed to fetch detail for ${entry.reference}: ${msg}`);
        totalErrors++;
        continue;
      }

      const parsed = parseAdvisoryDetail(detailHtml, entry.reference, entry.severity);

      // Use listing metadata as fallback
      if (!parsed.date && entry.date) {
        parsed.date = entry.date;
      }
      if (!parsed.severity && entry.severity) {
        parsed.severity = entry.severity;
      }

      if (insertAdvisory(db, parsed)) {
        totalInserted++;
        log(`  Inserted advisory: ${entry.reference} — ${parsed.title}`);
      } else {
        totalSkipped++;
      }
    }

    if (!hasNextPage) {
      log(`No more pages after page ${page + 1}`);
      break;
    }

    page++;
  }

  return { inserted: totalInserted, skipped: totalSkipped, errors: totalErrors };
}

// ---------------------------------------------------------------------------
// Crawl orchestration: CSIRT publications listing
// ---------------------------------------------------------------------------

async function crawlCsirtPublications(
  db: Database.Database,
): Promise<{ inserted: number; skipped: number; errors: number }> {
  log("\n=== Crawling: CSIRT Italia publications ===");

  let totalInserted = 0;
  let totalSkipped = 0;
  let totalErrors = 0;
  let page = 0;

  while (page < MAX_PAGES) {
    const start = page * 20;
    const listUrl = `${CSIRT_PUBLICATIONS_URL}?start=${start}&delta=20`;
    log(`Fetching publications listing page ${page + 1} (start=${start})`);

    let listHtml: string;
    try {
      listHtml = await fetchPage(listUrl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`Failed to fetch listing page ${page + 1}: ${msg}`);
      totalErrors++;
      break;
    }

    const { entries, hasNextPage } = parseCsirtPublicationsListing(listHtml);

    if (entries.length === 0) {
      log(`No entries found on page ${page + 1}, stopping`);
      break;
    }

    log(`Found ${entries.length} entries on page ${page + 1}`);

    for (const entry of entries) {
      // Resume mode: skip if already in DB
      if (FLAG_RESUME && referenceExists(db, "guidance", entry.reference)) {
        totalSkipped++;
        continue;
      }

      if (FLAG_DRY_RUN) {
        log(`  [DRY RUN] Would fetch: ${entry.reference} — ${entry.title}`);
        totalSkipped++;
        continue;
      }

      // Fetch detail page
      let detailHtml: string;
      try {
        detailHtml = await fetchPage(entry.url);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logError(`Failed to fetch detail for ${entry.reference}: ${msg}`);
        totalErrors++;
        continue;
      }

      const parsed = parsePublicationDetail(detailHtml, entry.reference);

      // Use listing date as fallback
      if (!parsed.date && entry.date) {
        parsed.date = entry.date;
      }

      if (insertGuidanceRow(db, parsed)) {
        totalInserted++;
        log(`  Inserted publication: ${entry.reference} — ${parsed.title}`);
      } else {
        totalSkipped++;
      }
    }

    if (!hasNextPage) {
      log(`No more pages after page ${page + 1}`);
      break;
    }

    page++;
  }

  return { inserted: totalInserted, skipped: totalSkipped, errors: totalErrors };
}

// ---------------------------------------------------------------------------
// Update framework document counts
// ---------------------------------------------------------------------------

function updateFrameworkCounts(db: Database.Database): void {
  log("\n=== Updating framework document counts ===");

  // Map series values to framework IDs
  const seriesMap: Record<string, string> = {
    PSNC: "psnc",
    MiSE: "misure-minime",
    NIS: "nis2-specifiche-base",
    Crittografia: "linee-guida-crittografia",
    "CSIRT Italia": "linee-guida-csirt",
    "Operational Summary": "linee-guida-csirt",
  };

  const rows = db
    .prepare("SELECT series, COUNT(*) as cnt FROM guidance WHERE series IS NOT NULL GROUP BY series")
    .all() as { series: string; cnt: number }[];

  for (const row of rows) {
    const frameworkId = seriesMap[row.series];
    if (frameworkId) {
      db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
        row.cnt,
        frameworkId,
      );
    }
  }

  // Also count ACN-series guidance under framework-nazionale
  const acnCount = (
    db.prepare("SELECT COUNT(*) as cnt FROM guidance WHERE series = 'ACN'").get() as { cnt: number }
  ).cnt;
  db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
    acnCount,
    "framework-nazionale",
  );

  log("Framework document counts updated");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("ACN ingestion crawler starting");
  log(`Flags: resume=${FLAG_RESUME} dry-run=${FLAG_DRY_RUN} force=${FLAG_FORCE} max-pages=${MAX_PAGES}`);

  const db = openDatabase();

  // Phase 1: Seed static frameworks and guidance (always runs)
  seedFrameworks(db);
  seedStaticGuidance(db);

  // Phase 2: Crawl CSIRT RSS feed (advisories from recent items)
  const rssResult = await crawlCsirtRss(db);

  // Phase 3: Crawl CSIRT alert & bulletin listing pages (comprehensive advisories)
  const alertsResult = await crawlCsirtAlerts(db);

  // Phase 4: Crawl CSIRT publications (operational summaries, reports, guidance)
  const pubsResult = await crawlCsirtPublications(db);

  // Phase 5: Update framework document counts
  if (!FLAG_DRY_RUN) {
    updateFrameworkCounts(db);
  }

  // --- Summary ---------------------------------------------------------------
  const guidanceCount = (
    db.prepare("SELECT COUNT(*) as cnt FROM guidance").get() as { cnt: number }
  ).cnt;
  const advisoryCount = (
    db.prepare("SELECT COUNT(*) as cnt FROM advisories").get() as { cnt: number }
  ).cnt;
  const frameworkCount = (
    db.prepare("SELECT COUNT(*) as cnt FROM frameworks").get() as { cnt: number }
  ).cnt;

  log("\n========================================");
  log("Ingestion complete");
  log("========================================");
  log(`RSS feed:      ${rssResult.inserted} inserted, ${rssResult.skipped} skipped, ${rssResult.errors} errors`);
  log(`Alerts:        ${alertsResult.inserted} inserted, ${alertsResult.skipped} skipped, ${alertsResult.errors} errors`);
  log(`Publications:  ${pubsResult.inserted} inserted, ${pubsResult.skipped} skipped, ${pubsResult.errors} errors`);
  log(`\nDatabase totals:`);
  log(`  Frameworks:  ${frameworkCount}`);
  log(`  Guidance:    ${guidanceCount}`);
  log(`  Advisories:  ${advisoryCount}`);
  log(`\nDatabase at: ${DB_PATH}`);

  db.close();
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  logError(`Fatal error: ${msg}`);
  process.exit(1);
});
