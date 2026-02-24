import { initDbAsync } from './dist/db/connection.js';
import { indexDetections } from './dist/indexer.js';
import fs from 'fs';

async function debug() {
  try {
    console.log('Step 1: Check if paths exist...');
    const paths = {
      sigma: './rules/sigma/rules',
      splunk: './rules/splunk/detections',
      elastic: './rules/elastic/rules',
      kql: './rules/sentinel/Hunting Queries'
    };

    for (const [type, path] of Object.entries(paths)) {
      const exists = fs.existsSync(path);
      console.log(`  ${type}: ${path} - ${exists ? '✅ EXISTS' : '❌ NOT FOUND'}`);
      
      if (exists) {
        const files = fs.readdirSync(path);
        console.log(`    Files/folders found: ${files.length}`);
        if (files.length > 0) {
          console.log(`    First item: ${files[0]}`);
        }
      }
    }

    console.log('\nStep 2: Initialize database...');
    await initDbAsync();
    console.log('  ✅ Database initialized');

    console.log('\nStep 3: Start indexing...');
    const result = indexDetections(
      [paths.sigma],
      [paths.splunk],
      [],
      [paths.elastic],
      [paths.kql]
    );

    console.log('\n=== RESULTS ===');
    console.log('Sigma:', result.sigma_indexed);
    console.log('Splunk:', result.splunk_indexed);
    console.log('Elastic:', result.elastic_indexed);
    console.log('KQL:', result.kql_indexed);
    console.log('TOTAL:', result.total);
    
    if (result.errors && result.errors.length > 0) {
      console.log('\nErrors:', result.errors.length);
      result.errors.slice(0, 5).forEach((e, i) => console.log(`  ${i+1}. ${e}`));
    }

    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

debug();
