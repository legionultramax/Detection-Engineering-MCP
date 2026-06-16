#!/usr/bin/env node
// One-shot: clear detections table and rebuild from on-disk rules.
// Uses the same env-var paths configured in claude_desktop_config.json.

import { initDbAsync, runStatement, runQuery, saveDb } from './dist/db/connection.js';
import { indexDetections } from './dist/indexer.js';

const REPO = process.cwd();
const SIGMA_PATHS  = [`${REPO}/rules/sigma/rules`];
const SPLUNK_PATHS = [`${REPO}/rules/splunk/detections`];
const ELASTIC_PATHS= [`${REPO}/rules/elastic/rules`];
const KQL_PATHS    = [`${REPO}/rules/sentinel/Hunting Queries`];
const STORY_PATHS  = [`${REPO}/rules/splunk/stories`];

const t0 = Date.now();
console.log('[reindex] Initializing DB...');
await initDbAsync();

const before = runQuery('SELECT COUNT(*) as c FROM detections')[0].c;
console.log(`[reindex] Detections currently in DB: ${before}`);

console.log('[reindex] Truncating detections table...');
runStatement('DELETE FROM detections');

console.log('[reindex] Indexing on-disk rules...');
const r = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);

saveDb();
const after = runQuery('SELECT COUNT(*) as c FROM detections')[0].c;
const secs = ((Date.now() - t0) / 1000).toFixed(1);

console.log('');
console.log('=== REINDEX COMPLETE ===');
console.log(`Sigma:   ${r.sigma_indexed}`);
console.log(`Splunk:  ${r.splunk_indexed}`);
console.log(`Elastic: ${r.elastic_indexed}`);
console.log(`KQL:     ${r.kql_indexed}`);
console.log(`Stories: ${r.stories_indexed}`);
console.log(`Total:   ${r.total}  (DB now has ${after}, was ${before})`);
console.log(`Time:    ${secs}s`);
process.exit(0);
