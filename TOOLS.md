# Tools

This MCP server exposes 6 tools under the `it_cyber_` prefix.

All responses include a `_meta` field with disclaimer, data_age, copyright, and source_url.
Search results and single-document responses include a `_citation` field for entity linking.
Error responses include `error`, `_error_type`, and `_meta` fields.

---

## it_cyber_search_guidance

Full-text search across ACN guidance documents. Covers Piano Strategico Nazionale per la Cybersicurezza, Misure Minime di Sicurezza, NIS2 implementation guidance, and technical publications.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `patch management`, `network security`) |
| `type` | string | no | Filter by type: `guidance`, `framework`, `technical`, `board` |
| `series` | string | no | Filter by series: `PSNC`, `MiSE`, `ACN`, `NIS2` |
| `status` | string | no | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | no | Max results (default 20, max 100) |

**Output:** `{ results: GuidanceWithCitation[], count: number, _meta: Meta }`

---

## it_cyber_get_guidance

Get a specific ACN guidance document by reference.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | ACN document reference (e.g., `ACN-LN-2023`, `ACN-PSNC-2022`) |

**Output:** Full guidance document with `_citation` and `_meta`.

---

## it_cyber_search_advisories

Search CSIRT-ITA security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `ransomware`, `zero-day`, `supply chain`) |
| `severity` | string | no | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | no | Max results (default 20, max 100) |

**Output:** `{ results: AdvisoryWithCitation[], count: number, _meta: Meta }`

---

## it_cyber_get_advisory

Get a specific CSIRT-ITA security advisory by reference.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | CSIRT-ITA advisory reference (e.g., `CSIRT-IT-ADV-2024-001`) |

**Output:** Full advisory with `_citation` and `_meta`.

---

## it_cyber_list_frameworks

List all ACN frameworks and guidance series covered in this MCP.

**Input:** None

**Output:** `{ frameworks: Framework[], count: number, _meta: Meta }`

---

## it_cyber_about

Return metadata about this MCP server: version, data source, coverage summary, and tool list.

**Input:** None

**Output:** Server metadata object with `_meta`.

---

## Shared types

### Meta

```json
{
  "disclaimer": "string",
  "data_age": "YYYY-MM-DD",
  "copyright": "string",
  "source_url": "string"
}
```

### Citation

```json
{
  "canonical_ref": "string",
  "display_text": "string",
  "aliases": ["string"],
  "source_url": "string",
  "lookup": {
    "tool": "string",
    "args": { "reference": "string" }
  }
}
```

### Error response

```json
{
  "error": "string",
  "_error_type": "not_found | tool_error | unknown_tool | internal_error",
  "_meta": { ... }
}
```
