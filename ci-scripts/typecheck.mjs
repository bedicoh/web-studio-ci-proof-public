#!/usr/bin/env node
// typecheck.mjs — vérification réelle et déterministe, sans dépendance externe (aucun compilateur
// TypeScript installé dans ce projet minimal) : chaque fichier de configuration JSON attendu doit
// être un JSON valide et structurellement conforme à son schéma minimal. Échoue réellement si un
// fichier est absent, illisible, ou syntaxiquement/structurellement invalide.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const CHECKS = [
  {
    file: 'package.json',
    validate: (v) => v !== null && typeof v === 'object' && typeof v.name === 'string',
  },
  {
    file: 'studio.config.json',
    validate: (v) => v !== null && typeof v === 'object' && typeof v.profile === 'string' && typeof v.publicInterface === 'boolean',
  },
  {
    file: 'studio.guardrails.lock.json',
    validate: (v) => v !== null && typeof v === 'object' && v.pinnedFiles !== null && typeof v.pinnedFiles === 'object',
  },
];

let failed = false;
for (const { file, validate } of CHECKS) {
  const full = path.join(ROOT, file);
  try {
    const raw = readFileSync(full, 'utf8');
    const parsed = JSON.parse(raw);
    if (!validate(parsed)) {
      failed = true;
      console.error(`typecheck: ECHEC ${file} — structure invalide.`);
      continue;
    }
    console.log(`typecheck: OK ${file}`);
  } catch (err) {
    failed = true;
    console.error(`typecheck: ECHEC ${file} — ${err.message}`);
  }
}

process.exit(failed ? 1 : 0);
