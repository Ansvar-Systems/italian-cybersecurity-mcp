/**
 * Seed the ACN database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["ACN_DB_PATH"] ?? "data/acn.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks --------------------------------------------------------------

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "psnc",
    name: "Piano Strategico Nazionale per la Cybersicurezza 2022-2026",
    name_en: "National Cybersecurity Strategic Plan 2022-2026",
    description: "Il Piano Strategico Nazionale per la Cybersicurezza definisce gli obiettivi strategici dell'Italia in materia di cybersicurezza per il periodo 2022-2026. Articolato in tre aree principali: protezione, risposta e sviluppo.",
    document_count: 1,
  },
  {
    id: "misure-minime",
    name: "Misure Minime di Sicurezza ICT per le Pubbliche Amministrazioni",
    name_en: "Minimum ICT Security Measures for Public Administrations",
    description: "Le Misure Minime di Sicurezza ICT definiscono il livello di sicurezza minimo che le pubbliche amministrazioni italiane devono garantire ai propri sistemi informatici. Definite in tre livelli: minimo, standard e avanzato.",
    document_count: 1,
  },
  {
    id: "framework-nazionale",
    name: "Framework Nazionale per la Cybersecurity e la Data Protection",
    name_en: "National Cybersecurity and Data Protection Framework",
    description: "Adattamento italiano del NIST Cybersecurity Framework, integrato con i requisiti del GDPR. Fornisce una guida strutturata per la gestione del rischio cyber nelle organizzazioni italiane.",
    document_count: 1,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);

for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}

console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance ----------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "ACN-PSNC-2022",
    title: "Piano Strategico Nazionale per la Cybersicurezza 2022-2026",
    title_en: "National Cybersecurity Strategic Plan 2022-2026",
    date: "2022-05-25",
    type: "framework",
    series: "PSNC",
    summary: "Il Piano Strategico Nazionale per la Cybersicurezza 2022-2026 definisce gli obiettivi e le azioni dell'Italia per rafforzare la propria postura di sicurezza cibernetica. Prevede 82 misure concrete organizzate in tre aree: protezione, risposta e sviluppo.",
    full_text: "Il Piano Strategico Nazionale per la Cybersicurezza 2022-2026 e il documento che definisce la visione e gli obiettivi strategici dell'Italia in materia di cybersicurezza. Adottato dall'Agenzia per la Cybersicurezza Nazionale (ACN). Tre aree strategiche: (1) Protezione — rafforzare la resilienza dei sistemi IT/OT della PA e delle infrastrutture critiche, completare l'implementazione della Direttiva NIS e NIS2, sviluppare capacita di difesa cibernetica. (2) Risposta — potenziare le capacita di risposta agli incidenti del CSIRT Italia, sviluppare le capacita di intelligence sulle minacce, rafforzare la cooperazione internazionale. (3) Sviluppo — promuovere la ricerca e l'innovazione in cybersicurezza, sviluppare competenze e formare esperti, sostenere l'industria italiana della cybersicurezza. Il piano prevede un investimento complessivo di circa 623 milioni di euro nel periodo 2022-2026, finanziato anche attraverso i fondi del Piano Nazionale di Ripresa e Resilienza (PNRR).",
    topics: JSON.stringify(["strategia", "PA", "infrastrutture-critiche", "PNRR", "NIS2"]),
    status: "current",
  },
  {
    reference: "ACN-MS-2017",
    title: "Misure Minime di Sicurezza ICT per le Pubbliche Amministrazioni",
    title_en: "Minimum ICT Security Measures for Public Administrations",
    date: "2017-04-17",
    type: "framework",
    series: "MiSE",
    summary: "Documento che definisce le misure minime di sicurezza ICT obbligatorie per le pubbliche amministrazioni italiane. Articolato in tre livelli (minimo, standard, avanzato) e basato sui 20 Controlli CIS. Adottato con Circolare AgID n. 2/2017.",
    full_text: "Le Misure Minime di Sicurezza ICT per le Pubbliche Amministrazioni sono state adottate con Circolare AgID n. 2/2017 e sono obbligatorie per tutte le PA italiane. Si basano sui Critical Security Controls (CIS Controls) e definiscono tre livelli di sicurezza: (1) Livello Minimo — il livello che ogni PA deve necessariamente raggiungere. Comprende inventario dispositivi, inventario software, protezione da malware, valutazione continua delle vulnerabilita, gestione delle configurazioni sicure, protezione dei dati, difese perimetrali, capacita di risposta agli incidenti. (2) Livello Standard — il livello che la maggior parte delle PA deve raggiungere per una protezione adeguata. Aggiunge controlli avanzati di accesso, protezione dei dati sensibili, audit log, sicurezza delle reti wireless, addestramento del personale. (3) Livello Avanzato — per le PA che gestiscono dati critici o infrastrutture essenziali. Include penetration testing, sicurezza avanzata dei sistemi, controllo degli accessi privilegiati, risposta avanzata agli incidenti. Il documento e stato aggiornato nel 2020 per allinearlo ai nuovi controlli CIS v7.1.",
    topics: JSON.stringify(["PA", "sicurezza-ICT", "CIS-controls", "livelli-sicurezza"]),
    status: "current",
  },
  {
    reference: "ACN-FN-2022",
    title: "Framework Nazionale per la Cybersecurity e la Data Protection v2.0",
    title_en: "National Cybersecurity and Data Protection Framework v2.0",
    date: "2022-01-01",
    type: "framework",
    series: "ACN",
    summary: "Versione 2.0 del Framework Nazionale, adattamento del NIST CSF integrato con GDPR e NIS. Organizzato in cinque funzioni (Identificare, Proteggere, Rilevare, Rispondere, Ripristinare) con 108 sottocategorie di controllo.",
    full_text: "Il Framework Nazionale per la Cybersecurity e la Data Protection v2.0 e uno strumento volontario per la gestione del rischio cyber nelle organizzazioni italiane, pubbliche e private. E un adattamento del NIST Cybersecurity Framework integrato con i requisiti del GDPR, della Direttiva NIS e della Direttiva NIS2. Struttura del Framework: (1) Identificare (Identify) — comprendere il contesto organizzativo, la gestione del rischio, e i sistemi informativi critici; (2) Proteggere (Protect) — implementare salvaguardie per garantire la continuita dei servizi critici; (3) Rilevare (Detect) — implementare attivita per identificare il verificarsi di eventi di cybersecurity; (4) Rispondere (Respond) — sviluppare e attuare le azioni appropriate in risposta a un incidente di cybersecurity; (5) Ripristinare (Recover) — attuare piani per la resilienza e ripristinare capacita e servizi compromessi da un incidente. Il Framework include anche una dimensione aggiuntiva dedicata alla protezione dei dati personali, in linea con i requisiti del GDPR.",
    topics: JSON.stringify(["NIST-CSF", "GDPR", "gestione-rischio", "NIS2"]),
    status: "current",
  },
  {
    reference: "ACN-LN-2023",
    title: "Linee Guida per la sicurezza delle Infrastrutture Critiche",
    title_en: "Security Guidelines for Critical Infrastructure",
    date: "2023-09-01",
    type: "guidance",
    series: "ACN",
    summary: "Linee guida dell'ACN per la protezione delle infrastrutture critiche nazionali. Copreno la valutazione del rischio, le misure di sicurezza fisiche e logiche, la continuita operativa e la notifica degli incidenti per i settori energia, trasporti, acqua e telecomunicazioni.",
    full_text: "Le linee guida dell'ACN per la sicurezza delle infrastrutture critiche si applicano agli Operatori di Servizi Essenziali (OSE) e ai Fornitori di Servizi Digitali (FSD) identificati ai sensi del D.Lgs. 65/2018 (NIS). I settori coperti includono energia (produzione, trasmissione e distribuzione elettrica; produzione, raffinazione e stoccaggio di petrolio e gas), trasporti, acqua potabile, infrastrutture digitali, operatori sanitari e banche. Principi fondamentali: (1) Approccio basato sul rischio — le misure di sicurezza devono essere proporzionate al rischio reale; (2) Sicurezza by design — la sicurezza deve essere integrata fin dalla progettazione dei sistemi; (3) Difesa in profondita — utilizzo di molteplici livelli di sicurezza; (4) Resilienza — capacita di resistere e recuperare da incidenti. Obblighi di notifica: gli incidenti con impatto significativo sulla continuita dei servizi essenziali devono essere notificati al CSIRT Italia entro 24 ore.",
    topics: JSON.stringify(["infrastrutture-critiche", "OSE", "NIS", "rischio", "continuita-operativa"]),
    status: "current",
  },
  {
    reference: "ACN-CLOUD-PA-2023",
    title: "Strategia Cloud Italia — Linee Guida per la migrazione al Cloud della PA",
    title_en: "Cloud Italy Strategy — Migration Guidelines for Public Administrations",
    date: "2023-03-01",
    type: "guidance",
    series: "ACN",
    summary: "Linee guida per la migrazione dei sistemi informativi delle pubbliche amministrazioni italiane verso il cloud. Definisce tre classi di dati/servizi (ordinari, critici, strategici) con requisiti di sicurezza differenziati e i criteri per la qualificazione dei servizi cloud per la PA.",
    full_text: "La Strategia Cloud Italia mira a consolidare i data center della PA e migrarli verso infrastrutture cloud sicure e certificate. L'ACN e responsabile della qualificazione dei servizi cloud per la Pubblica Amministrazione. Classificazione dei dati e servizi: (1) Ordinari — dati che non comportano rischi elevati; possono migrare su cloud certificati CSP in ambito UE; (2) Critici — dati che possono comportare rischi per l'ordine pubblico, la sicurezza o l'erogazione di servizi essenziali; richiedono cloud qualificati ACN; (3) Strategici — dati la cui compromissione potrebbe arrecare danni alla sicurezza nazionale; richiedono il Polo Strategico Nazionale (PSN). Il Polo Strategico Nazionale e l'infrastruttura cloud sovrana italiana, gestita da un consorzio privato con controllo governativo, che ospita i dati strategici della PA italiana.",
    topics: JSON.stringify(["cloud", "PA", "PSN", "qualificazione", "migrazione"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(
      g.reference, g.title, g.title_en, g.date, g.type,
      g.series, g.summary, g.full_text, g.topics, g.status,
    );
  }
});

insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories --------------------------------------------------------------

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "CSIRT-IT-ADV-2024-001",
    title: "Campagna di attacchi ransomware contro organizzazioni italiane — LockBit 3.0",
    date: "2024-01-20",
    severity: "critical",
    affected_products: JSON.stringify(["VMware ESXi", "Windows Server", "NAS Synology"]),
    summary: "Il CSIRT Italia segnala una campagna di attacchi ransomware LockBit 3.0 che colpisce organizzazioni italiane in diversi settori. Gli attaccanti sfruttano vulnerabilita non patchate in VMware ESXi e sistemi Windows per ottenere l'accesso iniziale.",
    full_text: "Il CSIRT Italia ha rilevato una campagna di attacchi ransomware condotta dal gruppo LockBit 3.0 che sta colpendo organizzazioni italiane nei settori manifatturiero, sanitario, professionale e della PA. Vettori di attacco identificati: sfruttamento di vulnerabilita in VMware ESXi (CVE-2021-21985, CVE-2021-21986), vulnerabilita nel protocollo RDP, e uso di credenziali compromesse acquistate su forum criminali. Tattiche post-compromissione: movimento laterale tramite PsExec e Windows Management Instrumentation, esfiltrazione dati prima della cifratura (doppia estorsione), disabilitazione dei backup e dei shadow copy. Raccomandazioni: applicare immediatamente le patch disponibili, implementare l'autenticazione a piu fattori, segmentare la rete, testare i backup. Non pagare il riscatto e segnalare al CSIRT Italia.",
    cve_references: JSON.stringify(["CVE-2021-21985", "CVE-2021-21986", "CVE-2023-20269"]),
  },
  {
    reference: "CSIRT-IT-ADV-2023-015",
    title: "Vulnerabilita critica in Citrix ADC e Gateway — Sfruttamento attivo",
    date: "2023-07-18",
    severity: "critical",
    affected_products: JSON.stringify(["Citrix ADC", "Citrix Gateway"]),
    summary: "Il CSIRT Italia emette un'allerta per una vulnerabilita critica nei prodotti Citrix ADC e Gateway (CVE-2023-3519) che consente l'esecuzione di codice remoto non autenticata. La vulnerabilita e attivamente sfruttata da attori malevoli.",
    full_text: "CVE-2023-3519 (CVSS 9.8) e una vulnerabilita di tipo stack overflow nel Citrix ADC e Gateway che consente a un attaccante remoto non autenticato di eseguire codice arbitrario. La vulnerabilita colpisce i dispositivi configurati come gateway (server virtuale VPN, proxy ICA, CVPN) o come AAA virtual server. Fortinet e altri vendor di threat intelligence hanno osservato lo sfruttamento attivo di questa vulnerabilita da luglio 2023, con attori che hanno installato webshell per mantenere l'accesso persistente. Versioni affectate: NetScaler ADC e NetScaler Gateway 13.1 prima di 13.1-49.13, 13.0 prima di 13.0-91.13, 12.1 prima di 12.1-65.15. Azioni immediate: applicare immediatamente le patch Citrix. Verificare la presenza di webshell o file sospetti nelle directory /netscaler/ e /var/nslog/. Analizzare i log di accesso per attivita anomale. Segnalare compromissioni al CSIRT Italia.",
    cve_references: JSON.stringify(["CVE-2023-3519", "CVE-2023-3466", "CVE-2023-3467"]),
  },
  {
    reference: "CSIRT-IT-ADV-2024-012",
    title: "Campagna di phishing mirata a enti pubblici italiani — Emotet",
    date: "2024-03-05",
    severity: "high",
    affected_products: JSON.stringify(["Microsoft Office", "Windows"]),
    summary: "Il CSIRT Italia segnala una nuova campagna di phishing che distribuisce il malware Emotet mediante email apparentemente provenienti da enti governativi italiani. Le email contengono allegati Word o PDF con macro maligne o link a siti compromessi.",
    full_text: "Il CSIRT Italia ha rilevato una nuova ondata di campagne di phishing mirate che utilizzano il malware Emotet per colpire enti pubblici e aziende italiane. Caratteristiche della campagna: le email sembrano provenire da indirizzi riconducibili a enti governativi italiani (INPS, Agenzia delle Entrate, Ministeri). Gli allegati sono documenti Word o PDF con nomi che richiamano fatture, comunicazioni ufficiali o avvisi di pagamento. I documenti contengono macro o exploit che scaricano ed eseguono Emotet. Una volta installato, Emotet funge da dropper per ulteriori payload (Qakbot, IcedID, ransomware). Misure di mitigazione: disabilitare l'esecuzione automatica delle macro in Office, formare il personale al riconoscimento del phishing, implementare filtri email avanzati con analisi sandbox, segmentare la rete per limitare la propagazione. Indicatori di compromissione (IoC) disponibili sul portale CSIRT Italia.",
    cve_references: JSON.stringify([]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(
      a.reference, a.title, a.date, a.severity,
      a.affected_products, a.summary, a.full_text, a.cve_references,
    );
  }
});

insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
