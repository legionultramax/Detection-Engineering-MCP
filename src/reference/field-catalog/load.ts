// Typed access to the derived field catalog.
//
// catalog.json is produced by scripts/build-field-catalog.mjs from the local
// corpus and the vendored CrowdStrike dictionary. It is derived, not authored —
// regenerate it rather than hand-editing.

import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export interface KqlCatalog {
  confidence: string;
  source: string;
  minSupport: number;
  tables: Record<string, number>;
  coreTables: Record<string, number>;
  customTableNote: string;
  fields: Record<string, number>;
  tableFields: Record<string, Record<string, number>>;
}

export interface SplMacro {
  kind: 'filter' | 'datasource' | 'utility' | 'external' | 'unresolved';
  references: number;
  expansion: string | null;
  note: string | null;
}

export interface SplCatalog {
  confidence: string;
  source: string;
  macroDirFound: boolean;
  dataModels: Record<string, number>;
  fields: Record<string, number>;
  commands: Record<string, number>;
  macros: Record<string, SplMacro>;
  macroSummary: Record<string, number>;
  macroInvocations: number;
}

export interface CqlEvent {
  platforms: string[];
  documented: boolean;
}

export interface CqlCatalog {
  confidence: string;
  source: string;
  authority: string;
  eventCount: number;
  documentedCount: number;
  events: Record<string, CqlEvent>;
}

export interface FieldCatalog {
  generated: string;
  generator: string;
  note: string;
  kql: KqlCatalog;
  spl: SplCatalog;
  cql: CqlCatalog;
}

let cached: FieldCatalog | null = null;
let loadError: string | null = null;

function catalogPath(): string {
  // dist/reference/field-catalog/load.js at runtime; the JSON is not compiled
  // by tsc, so resolve it relative to the source tree it was written into.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.join(here, 'catalog.json'),
    path.resolve(here, '..', '..', '..', 'src', 'reference', 'field-catalog', 'catalog.json'),
    path.resolve(here, '..', '..', 'src', 'reference', 'field-catalog', 'catalog.json'),
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  return candidates[0];
}

/**
 * Load the catalog, or return null if it has not been built.
 *
 * Returning null rather than throwing is deliberate: a missing catalog should
 * degrade validation to "cannot check fields", reported honestly, not take the
 * whole server down. Callers must handle null and say so.
 */
export function getFieldCatalog(): FieldCatalog | null {
  if (cached) return cached;
  if (loadError) return null;
  const p = catalogPath();
  try {
    cached = JSON.parse(readFileSync(p, 'utf8')) as FieldCatalog;
    return cached;
  } catch (err) {
    loadError = err instanceof Error ? err.message : String(err);
    console.error(
      `[catalog] could not load ${p}: ${loadError}. ` +
      'Field validation will be skipped — run "npm run catalog:build".'
    );
    return null;
  }
}

/** Why the catalog is unavailable, for reporting rather than silent degradation. */
export function getCatalogError(): string | null {
  return loadError;
}

/**
 * Nearest known names, for "did you mean" on an unknown field.
 *
 * Plain edit distance over a candidate list. The point is not linguistic
 * sophistication — it is that a model correcting `ProcessCommandline` to
 * `ProcessCommandLine` needs the right spelling put in front of it, and a
 * blocking error with no suggestion invites a second guess.
 */
export function nearest(name: string, candidates: string[], limit = 3): string[] {
  const target = name.toLowerCase();
  const scored: Array<{ n: string; d: number }> = [];
  for (const c of candidates) {
    const d = editDistance(target, c.toLowerCase());
    // Only offer genuinely close matches; a distant "suggestion" is noise.
    if (d <= Math.max(2, Math.floor(target.length / 3))) scored.push({ n: c, d });
  }
  scored.sort((a, b) => a.d - b.d || a.n.length - b.n.length);
  return scored.slice(0, limit).map(s => s.n);
}

function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 4) return 99;
  const prev = new Array<number>(b.length + 1);
  const cur = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j];
  }
  return prev[b.length];
}
