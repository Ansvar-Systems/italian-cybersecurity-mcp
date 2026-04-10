# Coverage

This document describes the data corpus ingested into the Italian Cybersecurity MCP server.

## Sources

### ACN — Agenzia per la Cybersicurezza Nazionale

**Portal:** https://www.acn.gov.it/

The primary source for all guidance documents. ACN is Italy's National Cybersecurity Agency, established by Legislative Decree 82/2021, responsible for national cybersecurity strategy and the implementation of NIS2 in Italy.

| Series | Description | Example references |
|--------|-------------|-------------------|
| PSNC   | Piano Strategico Nazionale per la Cybersicurezza — the national strategic cybersecurity plan | ACN-PSNC-2022 |
| MiSE   | Misure Minime di Sicurezza ICT — minimum ICT security measures for public administrations | ACN-MS-2023 |
| ACN    | General ACN technical publications and guidelines | ACN-LN-2023 |
| NIS2   | NIS2 Directive implementation guidance for operators and essential entities | ACN-NIS2-2024 |

### CSIRT-ITA — Computer Security Incident Response Team Italia

**Portal:** https://www.csirt.gov.it/

Italy's national CSIRT, operating under ACN. Publishes security advisories, vulnerability alerts, and incident reports for critical infrastructure operators and public administrations.

| Type | Description | Example references |
|------|-------------|-------------------|
| Advisory | Security advisories for specific vulnerabilities and threats | CSIRT-IT-ADV-2024-001 |
| Alert | High-urgency alerts for active exploitation or ongoing incidents | CSIRT-IT-ALR-2024-001 |

## Document types

| Type | Description |
|------|-------------|
| `guidance` | Operational cybersecurity guidance for organisations |
| `framework` | Structured frameworks (e.g., CAF-equivalent, NIS2 compliance) |
| `technical` | Technical specifications and implementation notes |
| `board` | Board-level and executive cybersecurity guidance |

## Coverage scope

- **Temporal coverage:** ACN publications from 2022 onwards; CSIRT-ITA advisories from 2023 onwards
- **Languages:** Documents indexed in both Italian (original) and English (translated titles where available)
- **Update cadence:** Ingested on demand via the `ingest` workflow; freshness checked weekly

## Out of scope

- Regional CERT publications
- Sector-specific regulators (AGCOM, IVASS, Banca d'Italia)
- EU-level publications (ENISA) — covered in separate MCPs
