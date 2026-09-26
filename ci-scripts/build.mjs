#!/usr/bin/env node
// build.mjs — build réel et déterministe, sans dépendance externe : lit src/index.mjs et écrit une
// copie vérifiée dans dist/index.mjs. Échoue réellement si la source est absente ou si la copie
// écrite ne correspond pas exactement à la source lue (intégrité du build vérifiée, pas supposée).

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const srcPath = path.join(ROOT, 'src', 'index.mjs');
const distDir = path.join(ROOT, 'dist');
const distPath = path.join(distDir, 'index.mjs');

const source = readFileSync(srcPath, 'utf8');
mkdirSync(distDir, { recursive: true });
writeFileSync(distPath, source, 'utf8');

const written = readFileSync(distPath, 'utf8');
if (written !== source) {
  console.error('build: ECHEC — le fichier écrit ne correspond pas à la source lue.');
  process.exit(1);
}

console.log(`build: OK — ${path.relative(ROOT, distPath)} écrit (${written.length} octets).`);
process.exit(0);
