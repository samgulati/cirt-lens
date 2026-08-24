import { readFileSync } from 'node:fs';

const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url)));
const forbidden = /\b(AGPL|SSPL|GPL-[123]|GPLv[123])\b/i;
const failures = Object.entries(lock.packages || {})
  .filter(([path, value]) => path && forbidden.test(value.license || ''))
  .map(([path, value]) => `${path}: ${value.license}`);

if (failures.length) {
  throw new Error(`Forbidden dependency licenses:\n${failures.join('\n')}`);
}
console.log(`Frontend dependency license policy passed (${Object.keys(lock.packages || {}).length - 1} packages checked).`);
