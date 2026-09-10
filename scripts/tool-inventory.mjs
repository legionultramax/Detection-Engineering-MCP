#!/usr/bin/env node
/**
 * Tool inventory — the authoritative answer to "how many tools does this server have?"
 *
 * Why this exists: nothing in this repo could report its own tool inventory, so the
 * number had to be hand-counted and hand-copied into the README badge, CLAUDE.md, and
 * the server instructions. They drifted, and static grepping cannot resolve the
 * disagreement — several tool modules align their values with padded whitespace
 * (`name:        'epss_score_lookup',`), and the exploit/ and community/ modules
 * generate tool names at runtime from config arrays (`${cfg.key}_search`), so no
 * regex can see them at all.
 *
 * This script loads the compiled registry and asks it directly. Runtime truth.
 *
 * Usage:
 *   node scripts/tool-inventory.mjs            # human-readable inventory
 *   node scripts/tool-inventory.mjs --json     # machine-readable
 *   node scripts/tool-inventory.mjs --check    # verify docs match reality; exit 1 on drift
 *   node scripts/tool-inventory.mjs --names    # bare sorted tool names, one per line
 *
 * Requires a build first: npm run build
 */

import { pathToFileURL, fileURLToPath } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';

// import.meta.dirname needs Node 20.11+; package.json declares >=18, so derive it.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const args = new Set(process.argv.slice(2));
const asJson = args.has('--json');
const asCheck = args.has('--check');
const asNames = args.has('--names');

const DIST_TOOLS = path.join(ROOT, 'dist', 'tools', 'index.js');

if (!existsSync(DIST_TOOLS)) {
  console.error(`error: ${path.relative(ROOT, DIST_TOOLS)} not found — run "npm run build" first.`);
  process.exit(2);
}

let mod;
try {
  mod = await import(pathToFileURL(DIST_TOOLS).href);
} catch (err) {
  console.error(`error: failed to load the tool registry: ${err?.message ?? err}`);
  console.error('If this is a database or filesystem error, a module is doing work at import');
  console.error('time that it should defer into its handler.');
  process.exit(2);
}

const { toolRegistry, registerAllTools, getToolsSummary } = mod;
if (typeof registerAllTools !== 'function' || !toolRegistry) {
  console.error('error: dist/tools/index.js did not export registerAllTools and toolRegistry.');
  process.exit(2);
}

// registerAllTools() logs its own counts to stderr; silence that so our output is clean.
const realErr = console.error;
console.error = () => {};
registerAllTools();
console.error = realErr;

const names = toolRegistry.getNames().slice().sort();
const total = toolRegistry.count();

// Per-module counts come from the registry's own summary where available, so this
// tracks module membership rather than a second hand-maintained list.
let byModule = {};
try {
  byModule = getToolsSummary?.()?.byModule ?? {};
} catch {
  byModule = {};
}

if (asNames) {
  console.log(names.join('\n'));
  process.exit(0);
}

if (asJson) {
  console.log(JSON.stringify({ total, byModule, names }, null, 2));
  process.exit(0);
}

// --- Documented claims, for drift detection -------------------------------------

/** Pull the Tools-<N>-blue shields.io badge count out of the README. */
function readmeBadgeCount() {
  const p = path.join(ROOT, 'README.md');
  if (!existsSync(p)) return null;
  const m = readFileSync(p, 'utf8').match(/badge\/Tools-(\d+)-/);
  return m ? Number(m[1]) : null;
}

/**
 * README prose that claims a count for the *whole* registry.
 *
 * Deliberately narrow. The original pattern matched any "N tools" anywhere,
 * which meant a legitimate sentence about a subset — "phase1-authoring is 25
 * tools" — was reported as drift against the registry total. A check that
 * fires on correct documentation trains people to ignore it.
 *
 * So only phrasings that assert the total count are considered: "exposes N
 * tools", "through N tools", "N tools across", "N tools registered". A
 * sentence about a profile or module says neither, and is left alone.
 */
function readmeProseCounts() {
  const p = path.join(ROOT, 'README.md');
  if (!existsSync(p)) return [];
  const text = readFileSync(p, 'utf8');
  const patterns = [
    /\b(?:expose[sd]?|exposing)\s+(\d{2,4})\s+tools\b/gi,
    /\bthrough\s+(\d{2,4})\s+tools\b/gi,
    /\b(\d{2,4})\s+tools\s+across\b/gi,
    /\b(\d{2,4})\s+tools\s+registered\b/gi,
    /\bregistry\s+has\s+(\d{2,4})\s+tools\b/gi,
  ];
  const out = [];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) out.push(Number(m[1]));
  }
  return out;
}

const badge = readmeBadgeCount();
const prose = readmeProseCounts();

if (asCheck) {
  const problems = [];
  if (badge !== null && badge !== total) {
    problems.push(`README badge claims ${badge} tools; registry has ${total}.`);
  }
  for (const n of new Set(prose)) {
    if (n !== total) problems.push(`README prose claims "${n} tools"; registry has ${total}.`);
  }
  if (problems.length === 0) {
    console.log(`ok — ${total} tools registered, documentation agrees.`);
    process.exit(0);
  }
  console.error(`tool inventory drift (registry has ${total}):`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error('\nUpdate the documentation, or the registry, so they agree.');
  process.exit(1);
}

// --- Human-readable output ------------------------------------------------------

console.log(`Registered tools: ${total}\n`);

const moduleEntries = Object.entries(byModule).sort((a, b) => b[1] - a[1]);
if (moduleEntries.length > 0) {
  const width = Math.max(...moduleEntries.map(([m]) => m.length));
  console.log('By module:');
  for (const [m, c] of moduleEntries) {
    console.log(`  ${m.padEnd(width)}  ${String(c).padStart(4)}`);
  }
  const summed = moduleEntries.reduce((a, [, c]) => a + c, 0);
  if (summed !== total) {
    console.log(`\n  note: module counts sum to ${summed}, registry holds ${total}.`);
    console.log('  A gap here means tools are registered outside the counted modules,');
    console.log('  or a module reports a count that does not match what it registers.');
  }
  console.log('');
}

if (badge !== null || prose.length > 0) {
  console.log('Documented claims:');
  if (badge !== null) {
    console.log(`  README badge      ${badge}${badge === total ? '  (agrees)' : `  <-- DRIFT, registry has ${total}`}`);
  }
  for (const n of new Set(prose)) {
    console.log(`  README prose      ${n}${n === total ? '  (agrees)' : `  <-- DRIFT, registry has ${total}`}`);
  }
  console.log('');
}

console.log('Tool names:');
const COLS = 3;
const colWidth = Math.max(...names.map(n => n.length)) + 2;
for (let i = 0; i < names.length; i += COLS) {
  console.log('  ' + names.slice(i, i + COLS).map(n => n.padEnd(colWidth)).join('').trimEnd());
}
