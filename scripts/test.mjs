import { readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

// Explicit filenames work on the declared Node 20 minimum and on Windows;
// Node 20's runner does not expand the quoted glob used in the monorepo.
const directory = resolve('dist/test');
const files = readdirSync(directory).filter((name) => name.endsWith('.test.js')).sort();
if (!files.length) throw new Error('No compiled SDK tests found');
const result = spawnSync(process.execPath, ['--test', '--test-reporter=spec', ...files.map((name) => resolve(directory, name))], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
