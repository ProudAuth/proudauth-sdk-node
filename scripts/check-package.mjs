import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const metadata = JSON.parse(readFileSync('package.json', 'utf8'));
const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
if (metadata.version !== lock.version || metadata.version !== lock.packages[''].version) throw new Error('Package and lockfile versions differ');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const result = spawnSync(npm, ['pack', '--ignore-scripts', '--dry-run', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
if (result.error) throw result.error;
if (result.status !== 0) throw new Error('Package dry run failed');
const [pack] = JSON.parse(result.stdout);
const files = new Set(pack.files.map((file) => file.path));
for (const item of ['README.md', 'LICENSE', 'NOTICE', 'package.json']) if (!files.has(item)) throw new Error(`Missing package file: ${item}`);
for (const entry of Object.values(metadata.exports)) {
  if (typeof entry === 'object') for (const path of Object.values(entry)) if (!files.has(path.replace(/^\.\//, ''))) throw new Error(`Missing public entry: ${path}`);
}
for (const name of files) if (/(^|\/)(test|testdata|node_modules|scripts)(\/|$)/.test(name)) throw new Error(`Unexpected private/build file in package: ${name}`);
console.log(`Verified ${pack.name}@${pack.version}: ${files.size} package files, all exported JS and declarations present`);
