#!/usr/bin/env node
// lint.mjs — vérification réelle et déterministe : syntaxe JS valide pour chaque fichier source du
// projet (src/, test/, ci-scripts/). Pas de dépendance externe (aucun eslint installé) : utilise
// `node --check`, qui échoue réellement sur un fichier syntaxiquement invalide.

import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function collectJsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...collectJsFiles(full));
    else if (/\.(mjs|js)$/.test(entry)) out.push(full);
  }
  return out;
}

const targets = [path.join(ROOT, 'src'), path.join(ROOT, 'test'), path.join(ROOT, 'ci-scripts')];
let files = [];
for (const dir of targets) {
  try {
    files.push(...collectJsFiles(dir));
  } catch {
    // dossier absent : ignoré, rien à vérifier dedans.
  }
}

let failed = false;
for (const file of files) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
    console.log(`lint: OK ${path.relative(ROOT, file)}`);
  } catch {
    failed = true;
    console.error(`lint: ECHEC ${path.relative(ROOT, file)}`);
  }
}

if (files.length === 0) {
  console.error('lint: aucun fichier source trouvé — échec explicite, pas un succès par défaut.');
  process.exit(1);
}

process.exit(failed ? 1 : 0);
