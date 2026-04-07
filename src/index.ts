#!/usr/bin/env node

/**
 * Italian Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying ACN (Agenzia per la Cybersicurezza Nazionale)
 * guidance documents, Cyber Essentials, CAF, 10 Steps to Cyber Security,
 * and security advisories.
 *
 * Tool prefix: it_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";
import { buildCitation } from "./utils/citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "italian-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "it_cyber_search_guidance",
    description:
      "Full-text search across NCSC guidance documents. Covers Piano Strategico Nazionale per la Cybersicurezza, Misure Minime di Sicurezza, NIS2 guidance, and technical publications. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'patch management', 'network security', 'incident response')",
        },
        type: {
          type: "string",
          enum: ["guidance", "framework", "technical", "board"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["PSNC", "MiSE", "ACN", "NIS2"],
          description: "Filter by NCSC series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "it_cyber_get_guidance",
    description:
      "Get a specific NCSC guidance document by reference (e.g., 'ACN-LN-2023', 'ACN-MS-2023', 'ACN-PSNC-2022').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "ACN document reference (e.g., 'ACN-LN-2023', 'ACN-PSNC-2022')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "it_cyber_search_advisories",
    description:
      "Search CSIRT-ITA security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'ransomware', 'zero-day', 'supply chain')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "it_cyber_get_advisory",
    description:
      "Get a specific NCSC security advisory by reference (e.g., 'CSIRT-IT-ADV-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "NCSC advisory reference (e.g., 'CSIRT-IT-ADV-2024-001')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "it_cyber_list_frameworks",
    description:
      "List all ACN frameworks and guidance series covered in this MCP, including the Piano Strategico Nazionale per la Cybersicurezza and NIS2 implementation guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "it_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guidance", "framework", "technical", "board"]).optional(),
  series: z.enum(["PSNC", "MiSE", "ACN", "NIS2"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "it_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "it_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        const d = doc as Record<string, unknown>;
        return textContent({
          ...doc,
          _citation: buildCitation(
            String(d.reference ?? parsed.reference),
            String(d.title ?? d.reference ?? parsed.reference),
            "it_cyber_get_guidance",
            { reference: parsed.reference },
          ),
        });
      }

      case "it_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "it_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        const adv = advisory as Record<string, unknown>;
        return textContent({
          ...advisory,
          _citation: buildCitation(
            String(adv.reference ?? parsed.reference),
            String(adv.title ?? adv.reference ?? parsed.reference),
            "it_cyber_get_advisory",
            { reference: parsed.reference },
          ),
        });
      }

      case "it_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "it_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "ACN (Agenzia per la Cybersicurezza Nazionale) MCP server. Provides access to NCSC guidance including Cyber Essentials, 10 Steps to Cyber Security, Cyber Assessment Framework (CAF), and security advisories.",
          data_source: "ACN (https://www.acn.gov.it/)",
          coverage: {
            guidance: "Piano Strategico Nazionale per la Cybersicurezza, Misure Minime di Sicurezza, NIS2 guidance",
            advisories: "CSIRT-ITA security advisories and alerts",
            frameworks: "PSNC, Misure Minime, NIS2",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
