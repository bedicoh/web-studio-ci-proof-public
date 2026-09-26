#!/usr/bin/env node
// studio-guardrails.mjs — gabarit source, dépôt méthode web-studio-system.
//
// Commande canonique de garde-fous techniques Web Studio (LOT G), complémentaire et strictement
// INDÉPENDANTE de `scripts/studio-verify.mjs` (voir docs/STUDIO_GUARDRAILS.md pour la doctrine
// complète). Aucun des deux scripts n'appelle l'autre, ni maintenant ni par conception future — une
// future CI pourra exécuter `npm run studio:verify && npm run studio:guardrails` sans aucun
// couplage d'implémentation entre les deux.
//
// Contraintes de conception (LOT G) :
// - Node natif uniquement : aucune dépendance npm propre à ce script.
// - Aucun réseau requis, aucune installation automatique.
// - Lecture seule sur le projet vérifié : ne modifie jamais un fichier du projet, y compris
//   `studio.guardrails.lock.json` — ce verrou n'est JAMAIS mis à jour automatiquement par ce script,
//   sous aucune condition, sous aucun flag (voir §0 bis).
// - Git est OBLIGATOIRE : ce script suppose un projet Git exploitable. Si Git est indisponible, si
//   une commande Git échoue, ou si le répertoire courant n'est pas un dépôt exploitable, chaque
//   contrôle qui en dépend (adoption-tracked, clean-tree, junk-files) répond `BLOCK` — jamais `SKIP`.
// - Sémantique de sortie à quatre statuts : `PASS` / `BLOCK` / `WARN` / `INFO` — distincte de la
//   sémantique PASS/FAIL/SKIP de `studio-verify.mjs`, volontairement, parce que ce script porte des
//   signaux qui nécessitent une interprétation humaine (`WARN`) que `studio-verify.mjs` ne modélise
//   pas. Seul un `BLOCK` rend le code de sortie non nul ; un `WARN` ne doit jamais devenir silencieux
//   (toujours affiché, toujours compté), mais n'affecte jamais seul le code de sortie.
// - Politique fail-closed : toute erreur interne empêchant de vérifier une condition normalement
//   `BLOCK` (lock illisible, fichier critique absent, Git indisponible pour un contrôle qui en a
//   besoin) est elle-même un `BLOCK` — jamais un `PASS` implicite, jamais un `SKIP`.
// - Il n'invoque jamais, sous aucune condition, les vérificateurs propres aux fixtures de gate de ce
//   dépôt (`fixtures/**/verify.mjs`, `prototypes/**/_verify.mjs`).
// - Ce qu'il ne fait jamais : scanner de secret par contenu, parseur SQL général, exécution
//   `npm audit`, CI, déploiement/rollback, jugement LLM comme gate déterministe — voir
//   docs/STUDIO_GUARDRAILS.md §12 pour la liste complète et la justification de chaque exclusion.
//
// ---------------------------------------------------------------------------
// 0 bis. Anti-test-gaming — ce que ce script garantit, et ce qu'il ne garantit jamais
// ---------------------------------------------------------------------------
// - Ce script ne met JAMAIS à jour son propre verrou (`studio.guardrails.lock.json`) : aucun flag,
//   aucun mode `--relock` n'existe. `--print-hashes` est strictement en lecture seule (affiche les
//   hashes actuels des fichiers critiques, n'écrit rien, ne modifie rien).
// - Toute divergence entre un hash verrouillé et le hash réel d'un fichier critique est un `BLOCK`,
//   sans exception et sans tentative de réparation automatique.
// - Un re-verrouillage (mise à jour délibérée de `studio.guardrails.lock.json` après une évolution
//   légitime de `scripts/studio-verify.mjs` ou de `scripts/studio-guardrails.mjs` eux-mêmes) est une
//   action humaine explicite, hors de ce script — jamais un effet de bord d'une exécution normale.
// - La modification des scripts critiques eux-mêmes nécessite une revue indépendante avant que leurs
//   nouveaux hashes soient reportés dans le verrou (même principe que `WORKFLOW.md` §8, « règle
//   issue du gate 2C-RUN » : un remplacement de vérificateur exige justification, couverture
//   équivalente ou supérieure démontrée, et confirmation par une revue indépendante).
// - LIMITE EXPLICITE, à ne jamais présenter autrement : ce pinning protège contre une dérive
//   accidentelle ou une modification non déclarée d'un script déjà de confiance. Il ne constitue PAS
//   une preuve cryptographique contre un attaquant qui contrôlerait SIMULTANÉMENT le script ET son
//   verrou (il modifierait alors les deux de façon cohérente, sans que ce script puisse le détecter
//   seul). L'ancre de confiance externe reste la revue indépendante humaine/Codex et, plus tard, une
//   CI qui recalcule et compare ces hashes depuis un environnement que l'agent ne contrôle pas.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';

const cwd = process.cwd();

/** @type {{ name: string, status: 'PASS'|'BLOCK'|'WARN'|'INFO', detail: string }[]} */
const results = [];

function record(name, status, detail) {
  results.push({ name, status, detail });
}

// ---------------------------------------------------------------------------
// Résolution de chemin stricte : existence, nature (fichier/répertoire) et casse exacte.
// Même helper que scripts/studio-verify.mjs (dupliqué volontairement : les deux scripts restent
// deux fichiers autonomes, sans import croisé — voir docs/STUDIO_GUARDRAILS.md §0).
// ---------------------------------------------------------------------------

function resolveExactEntry(baseDir, relPath) {
  const segments = relPath.split('/').filter(Boolean);
  let currentDir = baseDir;
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    let entries;
    try {
      entries = readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return { exists: false };
    }
    const match = entries.find((e) => e.name === segment);
    if (!match) return { exists: false };
    const nextPath = path.join(currentDir, match.name);
    const isLast = i === segments.length - 1;
    if (isLast) {
      let st;
      try {
        st = statSync(nextPath);
      } catch {
        return { exists: false };
      }
      return { exists: true, isFile: st.isFile(), isDirectory: st.isDirectory(), fullPath: nextPath };
    }
    if (!match.isDirectory()) return { exists: false };
    currentDir = nextPath;
  }
  return { exists: false };
}

function sha256OfFile(fullPath) {
  return createHash('sha256').update(readFileSync(fullPath)).digest('hex');
}

// ---------------------------------------------------------------------------
// D1 — Intégrité des scripts critiques (verrouillage SHA-256) — BLOCK
// ---------------------------------------------------------------------------

const CRITICAL_PINNED_FILES = ['scripts/studio-verify.mjs', 'scripts/studio-guardrails.mjs'];
const SHA256_RE = /^[0-9a-fA-F]{64}$/;

// --print-hashes : mode strictement en lecture seule, n'exécute aucun autre contrôle, ne touche
// jamais studio.guardrails.lock.json. Utilisé pour connaître les hashes actuels avant un
// re-verrouillage humain délibéré (voir §0 bis ci-dessus).
if (process.argv.includes('--print-hashes')) {
  console.log('STUDIO GUARDRAILS — --print-hashes (lecture seule, ne modifie jamais studio.guardrails.lock.json)');
  for (const relPath of CRITICAL_PINNED_FILES) {
    const entry = resolveExactEntry(cwd, relPath);
    if (!entry.exists || !entry.isFile) {
      console.log(`${relPath}: (absent ou casse incorrecte)`);
      continue;
    }
    try {
      console.log(`${relPath}: ${sha256OfFile(entry.fullPath)}`);
    } catch (err) {
      console.log(`${relPath}: (illisible : ${err.message})`);
    }
  }
  process.exit(0);
}

function loadLockFile() {
  const entry = resolveExactEntry(cwd, 'studio.guardrails.lock.json');
  if (!entry.exists || !entry.isFile) {
    return { ok: false, error: 'studio.guardrails.lock.json introuvable à la racine du projet (absent, répertoire, ou casse incorrecte).' };
  }
  let raw;
  try {
    raw = readFileSync(entry.fullPath, 'utf8');
  } catch (err) {
    return { ok: false, error: `studio.guardrails.lock.json illisible : ${err.message}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, error: `studio.guardrails.lock.json n'est pas un JSON valide : ${err.message}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: `studio.guardrails.lock.json doit être un objet JSON — trouvé : ${JSON.stringify(parsed)}.` };
  }
  if (parsed.schemaVersion !== 1) {
    return { ok: false, error: `schemaVersion attendu : 1 — trouvé : ${JSON.stringify(parsed.schemaVersion)}.` };
  }
  const pinnedFiles = parsed.pinnedFiles;
  if (pinnedFiles === null || typeof pinnedFiles !== 'object' || Array.isArray(pinnedFiles)) {
    return { ok: false, error: `pinnedFiles doit être un objet JSON — trouvé : ${JSON.stringify(pinnedFiles)}.` };
  }
  const keys = Object.keys(pinnedFiles);
  const expectedSet = new Set(CRITICAL_PINNED_FILES);
  const actualSet = new Set(keys);
  const missing = CRITICAL_PINNED_FILES.filter((f) => !actualSet.has(f));
  const unexpected = keys.filter((k) => !expectedSet.has(k));
  if (missing.length > 0 || unexpected.length > 0) {
    const parts = [];
    if (missing.length > 0) parts.push(`manquant(s) : ${missing.join(', ')}`);
    if (unexpected.length > 0) parts.push(`inattendu(s) : ${unexpected.join(', ')}`);
    return {
      ok: false,
      error: `pinnedFiles doit contenir exactement ${CRITICAL_PINNED_FILES.join(', ')} — ${parts.join(' ; ')}.`,
    };
  }
  for (const f of CRITICAL_PINNED_FILES) {
    const value = pinnedFiles[f];
    if (typeof value !== 'string' || !SHA256_RE.test(value)) {
      return { ok: false, error: `Hash pour "${f}" mal formé (attendu : SHA-256 hexadécimal, 64 caractères) — trouvé : ${JSON.stringify(value)}.` };
    }
  }
  return { ok: true, pinnedFiles };
}

function checkIntegrity() {
  const lock = loadLockFile();
  if (!lock.ok) {
    record('integrity', 'BLOCK', lock.error);
    return;
  }
  const problems = [];
  for (const relPath of CRITICAL_PINNED_FILES) {
    const entry = resolveExactEntry(cwd, relPath);
    if (!entry.exists || !entry.isFile) {
      problems.push(`${relPath} : fichier critique absent (ou casse incorrecte).`);
      continue;
    }
    let actualHash;
    try {
      actualHash = sha256OfFile(entry.fullPath);
    } catch (err) {
      problems.push(`${relPath} : illisible (${err.message}).`);
      continue;
    }
    const lockedHash = lock.pinnedFiles[relPath].toLowerCase();
    if (actualHash !== lockedHash) {
      problems.push(`${relPath} : hash différent du verrou (verrouillé ${lockedHash.slice(0, 12)}…, actuel ${actualHash.slice(0, 12)}…).`);
    }
  }
  if (problems.length > 0) {
    record('integrity', 'BLOCK', problems.join(' '));
  } else {
    record('integrity', 'PASS', `${CRITICAL_PINNED_FILES.length} fichier(s) critique(s) conforme(s) au verrou studio.guardrails.lock.json.`);
  }
}

// ---------------------------------------------------------------------------
// Instantanés Git partagés — calculés une fois, consommés par plusieurs contrôles.
// Git est OBLIGATOIRE pour ce script (§0). Une commande Git en échec fait BLOCK, fail-closed,
// chaque contrôle qui en dépend — jamais SKIP.
// ---------------------------------------------------------------------------

function runGitLsFiles() {
  const res = spawnSync('git', ['ls-files'], { cwd, encoding: 'utf8', shell: false });
  if (res.error) {
    return { ok: false, error: `Git indisponible ici : ${res.error.message}` };
  }
  if (res.status !== 0) {
    const stderr = (res.stderr || '').trim();
    return { ok: false, error: `"git ls-files" a échoué (code ${res.status}${stderr ? ` — ${stderr}` : ''}).` };
  }
  const files = (res.stdout || '').split('\n').map((l) => l.trim()).filter(Boolean);
  return { ok: true, files };
}

function runGitStatusPorcelain() {
  const res = spawnSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf8', shell: false });
  if (res.error) {
    return { ok: false, error: `Git indisponible ici : ${res.error.message}` };
  }
  if (res.status !== 0) {
    const stderr = (res.stderr || '').trim();
    return { ok: false, error: `"git status --porcelain" a échoué (code ${res.status}${stderr ? ` — ${stderr}` : ''}).` };
  }
  const lines = (res.stdout || '').split('\n').filter((l) => l.trim() !== '');
  return { ok: true, lines };
}

// ---------------------------------------------------------------------------
// D2 — Fichiers d'adoption obligatoires TRACKÉS par Git — BLOCK
//
// `studio-verify.mjs` contrôle déjà leur PRÉSENCE SUR DISQUE (casse exacte, fichier réel) — ce
// contrôle-ci n'est jamais réimplémenté ici. Ce guardrail vérifie l'angle complémentaire : ces mêmes
// chemins doivent aussi être suivis par Git (`git ls-files`), pas seulement présents localement. Un
// fichier jamais `git add`-é après adoption, ou masqué par `.gitignore`, passe `studio-verify.mjs`
// (qui ne regarde que le disque) sans être détecté — c'est exactement ce que ce contrôle couvre.
//
// Liste COMMUNE identique à ADOPTION_FILES_ALWAYS de scripts/studio-verify.mjs
// (docs/PROJECT_ADOPTION.md §3/§3.1, supports obligatoires pour TOUS les profils), étendue des
// quatre artefacts ajoutés par ce lot et par LOT C : `scripts/studio-guardrails.mjs`,
// `docs/STUDIO_GUARDRAILS.md`, `studio.config.json` et `studio.guardrails.lock.json` eux-mêmes —
// corrigé après revue Codex (REVIEW FAIL, P1 : ces deux derniers étaient omis, ce qui permettait un
// faux succès BLOCK lorsqu'ils étaient présents sur disque mais jamais suivis par Git, par exemple
// masqués par `.gitignore`). Duplication de données assumée : les deux scripts restent
// volontairement deux fichiers autonomes, sans import croisé (docs/STUDIO_GUARDRAILS.md §0).
// ---------------------------------------------------------------------------

const ADOPTION_FILES_REQUIRED = [
  'WORKFLOW.md',
  'CLAUDE.md',
  'AGENTS.md',
  'THIRD_PARTY_NOTICES.md',
  'scripts/studio-verify.mjs',
  'scripts/studio-guardrails.mjs',
  'studio.config.json',
  'studio.guardrails.lock.json',
  'docs/WEB_STUDIO_V1_SPEC.md',
  'docs/checklists/DELIVERY_CHECKLIST.md',
  'docs/AGENT_USAGE.md',
  'docs/FRONTEND_CRAFT_STANDARD.md',
  'docs/checklists/FRONTEND_CRAFT_AUDIT.md',
  'docs/SECURITY_ENGINEERING_STANDARD.md',
  'docs/MAINTAINABILITY_STANDARD.md',
  'docs/checklists/SECURITY_AUDIT.md',
  'docs/checklists/MAINTAINABILITY_AUDIT.md',
  'docs/TASK_HANDOFF_TEMPLATE.md',
  'docs/QA_REPORT_TEMPLATE.md',
  'docs/SECURITY_REPORT_TEMPLATE.md',
  'docs/FRONTEND_CRAFT_REPORT_TEMPLATE.md',
  'docs/THREAT_MODEL_TEMPLATE.md',
  'docs/MAINTAINABILITY_REPORT_TEMPLATE.md',
  'docs/EMIL_SKILLS_ADAPTATION.md',
  'docs/ECC_SECURITY_ADAPTATION.md',
  'docs/STUDIO_VERIFY.md',
  'docs/STUDIO_GUARDRAILS.md',
];

// Fichiers d'adoption conditionnés à `publicInterface=true` — identique à
// ADOPTION_FILES_PUBLIC_INTERFACE de scripts/studio-verify.mjs (docs/PROJECT_ADOPTION.md §3/§3.1).
const ADOPTION_FILES_PUBLIC_INTERFACE = [
  'docs/DESIGN_ANTI_GENERIC_STANDARD.md',
  'docs/checklists/DESIGN_IDENTITY_AUDIT.md',
  'docs/DESIGN_HANDOFF_STANDARD.md',
];

// Détermine la portée du contrôle D2 (fichiers conditionnels ou non) en lisant `studio.config.json`
// DEPUIS LE DISQUE (jamais via Git — la trackedness de ce fichier est vérifiée séparément, comme
// tout autre fichier de la liste commune ci-dessus). Ce n'est PAS une réimplémentation de la
// validation complète de studio-verify.mjs : seul `publicInterface` est nécessaire ici pour savoir
// quels chemins ajouter à la liste attendue. Toute incapacité à déterminer cette portée (fichier
// absent, illisible, JSON invalide, non-objet, `publicInterface` non booléen) est elle-même un
// `BLOCK` fail-closed pour ce contrôle — jamais une portée par défaut supposée.
function determineAdoptionScope() {
  const entry = resolveExactEntry(cwd, 'studio.config.json');
  if (!entry.exists || !entry.isFile) {
    return { ok: false, reason: 'studio.config.json absent (ou casse incorrecte) — impossible de déterminer la portée du suivi Git attendu (cannot determine adoption tracking scope).' };
  }
  let raw;
  try {
    raw = readFileSync(entry.fullPath, 'utf8');
  } catch (err) {
    return { ok: false, reason: `studio.config.json illisible — impossible de déterminer la portée du suivi Git attendu (cannot determine adoption tracking scope) : ${err.message}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, reason: `studio.config.json n'est pas un JSON valide — impossible de déterminer la portée du suivi Git attendu (cannot determine adoption tracking scope) : ${err.message}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'studio.config.json doit être un objet JSON — impossible de déterminer la portée du suivi Git attendu (cannot determine adoption tracking scope).' };
  }
  if (typeof parsed.publicInterface !== 'boolean') {
    return { ok: false, reason: `studio.config.json.publicInterface doit être un booléen — impossible de déterminer la portée du suivi Git attendu (cannot determine adoption tracking scope), trouvé : ${JSON.stringify(parsed.publicInterface)}.` };
  }
  return { ok: true, publicInterface: parsed.publicInterface };
}

function checkAdoptionTracked(lsFilesResult) {
  if (!lsFilesResult.ok) {
    record('adoption-tracked', 'BLOCK', `Impossible de vérifier — ${lsFilesResult.error} (Git obligatoire pour ce contrôle, fail-closed).`);
    return;
  }
  const tracked = new Set(lsFilesResult.files);
  const problems = [];

  const missingCommon = ADOPTION_FILES_REQUIRED.filter((f) => !tracked.has(f));
  if (missingCommon.length > 0) {
    problems.push(`Fichier(s) commun(s) non suivi(s) par Git (absent(s) de "git ls-files") : ${missingCommon.join(', ')}.`);
  }

  const scope = determineAdoptionScope();
  let conditionalChecked = 0;
  if (!scope.ok) {
    problems.push(scope.reason);
  } else if (scope.publicInterface) {
    const missingConditional = ADOPTION_FILES_PUBLIC_INTERFACE.filter((f) => !tracked.has(f));
    conditionalChecked = ADOPTION_FILES_PUBLIC_INTERFACE.length;
    if (missingConditional.length > 0) {
      problems.push(`Fichier(s) conditionnel(s) (publicInterface=true) non suivi(s) par Git : ${missingConditional.join(', ')}.`);
    }
  }

  if (problems.length === 0) {
    const total = ADOPTION_FILES_REQUIRED.length + conditionalChecked;
    record(
      'adoption-tracked',
      'PASS',
      `${total} fichier(s) d'adoption obligatoire(s) suivi(s) par Git${conditionalChecked > 0 ? ` (dont ${conditionalChecked} conditionnel(s), publicInterface=true)` : ''}.`,
    );
  } else {
    record('adoption-tracked', 'BLOCK', `${problems.join(' ')} Normal et attendu juste après adoption, avant le premier commit — mais un fichier masqué par .gitignore produit le même BLOCK, à examiner.`);
  }
}

// ---------------------------------------------------------------------------
// D3 — Working tree propre — BLOCK
//
// Contrôle de point de contrôle/livraison (checkpoint), pas une commande censée rester verte en
// continu pendant le développement. Les autres contrôles s'exécutent quand même pour fournir un
// rapport complet avant la sortie non nulle.
// ---------------------------------------------------------------------------

function checkCleanTree(statusResult) {
  if (!statusResult.ok) {
    record('clean-tree', 'BLOCK', `Impossible de vérifier — ${statusResult.error} (Git obligatoire pour ce contrôle, fail-closed).`);
    return;
  }
  if (statusResult.lines.length === 0) {
    record('clean-tree', 'PASS', 'Working tree propre (aucune modification non commitée).');
  } else {
    record('clean-tree', 'BLOCK', `Working tree contient ${statusResult.lines.length} changement(s) non commité(s).`);
  }
}

// ---------------------------------------------------------------------------
// D4 — Lockfile présent si dépendances déclarées — BLOCK
//
// Ne parse jamais le CONTENU d'un lockfile (existence seulement) ; ne tente aucune corrélation
// package.json/lockfile (reportée à la CI, nécessite une base de diff canonique — voir
// docs/STUDIO_GUARDRAILS.md §11).
// ---------------------------------------------------------------------------

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb'];
const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

function checkLockfile() {
  const entry = resolveExactEntry(cwd, 'package.json');
  if (!entry.exists || !entry.isFile) {
    record('lockfile', 'BLOCK', 'package.json introuvable (ou casse incorrecte) — impossible de déterminer si des dépendances sont déclarées, fail-closed.');
    return;
  }
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(entry.fullPath, 'utf8'));
  } catch (err) {
    record('lockfile', 'BLOCK', `package.json n'est pas un JSON valide — impossible de déterminer si des dépendances sont déclarées, fail-closed : ${err.message}`);
    return;
  }
  if (pkg === null || typeof pkg !== 'object' || Array.isArray(pkg)) {
    record(
      'lockfile',
      'BLOCK',
      `package.json doit être un objet JSON — impossible de déterminer si des dépendances sont déclarées, fail-closed (trouvé : ${JSON.stringify(pkg)}).`,
    );
    return;
  }
  let depCount = 0;
  for (const field of DEPENDENCY_FIELDS) {
    const value = pkg[field];
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      depCount += Object.keys(value).length;
    }
  }
  if (depCount === 0) {
    record('lockfile', 'PASS', 'Aucune dépendance déclarée (dependencies/devDependencies/peerDependencies/optionalDependencies) — lockfile non requis par ce contrôle.');
    return;
  }
  const present = LOCKFILE_NAMES.filter((name) => {
    const e = resolveExactEntry(cwd, name);
    return e.exists && e.isFile;
  });
  if (present.length > 0) {
    record('lockfile', 'PASS', `${depCount} dépendance(s) déclarée(s) ; fichier de verrouillage présent : ${present.join(', ')}.`);
  } else {
    record('lockfile', 'BLOCK', `${depCount} dépendance(s) déclarée(s) mais aucun fichier de verrouillage reconnu présent (${LOCKFILE_NAMES.join(', ')}).`);
  }
}

// ---------------------------------------------------------------------------
// D6 — Fichiers « poubelle » connus suivis par Git — WARN
//
// Liste fermée et minimale, comparaison par nom de fichier EXACT (basename), jamais de scanner de
// contenu, jamais de wildcard agressif, jamais de détection de secret.
// ---------------------------------------------------------------------------

const JUNK_BASENAMES = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);

function checkJunkFiles(lsFilesResult) {
  if (!lsFilesResult.ok) {
    record('junk-files', 'BLOCK', `Impossible de vérifier — ${lsFilesResult.error} (Git obligatoire pour ce contrôle, fail-closed).`);
    return;
  }
  const flagged = lsFilesResult.files.filter((f) => JUNK_BASENAMES.has(path.basename(f)));
  if (flagged.length === 0) {
    record('junk-files', 'PASS', 'Aucun fichier de la liste fermée (.DS_Store, Thumbs.db, desktop.ini) suivi par Git.');
  } else {
    record('junk-files', 'WARN', `Fichier(s) suivi(s) par Git correspondant à la liste fermée : ${flagged.join(', ')}.`);
  }
}

// ---------------------------------------------------------------------------
// Parcours de fichiers partagé (D8, D9) — exclut les répertoires lourds usuels et les extensions
// manifestement binaires (garde-fou de performance, pas une limite de sécurité).
// ---------------------------------------------------------------------------

const WALK_EXCLUDE_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'out', 'coverage', '.turbo', '.vercel']);
const BINARY_LIKE_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp4', '.mp3', '.wav', '.pdf', '.zip', '.gz', '.tar', '.7z', '.bin', '.exe',
]);
const MAX_SCAN_BYTES = 1_000_000; // 1 Mo : garde-fou de performance, pas une limite de sécurité.

function walkFiles(rootDir, excludeDirNames) {
  const collected = [];
  function walk(dir) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (excludeDirNames.has(entry.name)) continue;
        walk(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_LIKE_EXTENSIONS.has(ext)) continue;
        collected.push(path.join(dir, entry.name));
      }
    }
  }
  walk(rootDir);
  return collected;
}

function toRelPath(fullPath) {
  return path.relative(cwd, fullPath).split(path.sep).join('/');
}

// ---------------------------------------------------------------------------
// Détection de surface Supabase (partagée par D8 et D9) — implicite uniquement (pas de nouveau champ
// studio.config.json en V1) :
//   - présence du répertoire `supabase/migrations/` ; OU
//   - dépendance `@supabase/supabase-js` déclarée dans package.json (les 4 champs de dépendances).
// ---------------------------------------------------------------------------

function detectSupabase() {
  const migrationsEntry = resolveExactEntry(cwd, 'supabase/migrations');
  const migrationsPresent = migrationsEntry.exists && migrationsEntry.isDirectory;

  const pkgEntry = resolveExactEntry(cwd, 'package.json');
  let dependencyPresent = false;
  if (pkgEntry.exists && pkgEntry.isFile) {
    try {
      const pkg = JSON.parse(readFileSync(pkgEntry.fullPath, 'utf8'));
      if (pkg !== null && typeof pkg === 'object' && !Array.isArray(pkg)) {
        for (const field of DEPENDENCY_FIELDS) {
          const value = pkg[field];
          if (
            value !== null &&
            typeof value === 'object' &&
            !Array.isArray(value) &&
            Object.prototype.hasOwnProperty.call(value, '@supabase/supabase-js')
          ) {
            dependencyPresent = true;
            break;
          }
        }
      }
    } catch {
      // package.json illisible/invalide : ne fait pas échouer la détection Supabase (INFO
      // uniquement) ; le contrôle "lockfile" (D4) rapporte déjà cette anomalie séparément en BLOCK.
    }
  }

  if (!migrationsPresent && !dependencyPresent) {
    return { detected: false, method: null, migrationsDir: null };
  }
  return {
    detected: true,
    method: migrationsPresent ? 'migrations' : 'dependency',
    migrationsDir: migrationsPresent ? migrationsEntry.fullPath : null,
  };
}

// ---------------------------------------------------------------------------
// D8 — Occurrence littérale de "DISABLE ROW LEVEL SECURITY" dans les migrations — WARN
//
// Signal uniquement : ne conclut jamais à une vulnérabilité par lui-même, exige une revue
// security-auditor. Ne bloque jamais automatiquement sur DROP/TRUNCATE ou tout autre mot SQL.
//
// La phrase est recherchée après normalisation des espaces (tout run d'espaces/tabulations/sauts de
// ligne réduit à un seul espace) — corrigé après revue Codex (P2) : la recherche littérale brute
// manquait une phrase répartie sur plusieurs lignes SQL (ex. `DISABLE ROW\n  LEVEL SECURITY`),
// pourtant sémantiquement identique. Reste une recherche de texte, jamais un parseur SQL.
// ---------------------------------------------------------------------------

const RLS_DISABLE_PHRASE = 'disable row level security';

function normalizeWhitespace(text) {
  return text.replace(/\s+/g, ' ');
}

function checkRlsDisable(supabaseInfo) {
  if (!supabaseInfo.detected) {
    record('rls-disable', 'PASS', 'non applicable — Supabase non détecté.');
    return;
  }
  if (!supabaseInfo.migrationsDir) {
    record('rls-disable', 'PASS', "Supabase détecté (dépendance), mais supabase/migrations/ absent — aucune migration textuelle à analyser.");
    return;
  }
  const files = walkFiles(supabaseInfo.migrationsDir, WALK_EXCLUDE_DIRS);
  const matched = [];
  for (const filePath of files) {
    let content;
    try {
      const stat = statSync(filePath);
      if (stat.size > MAX_SCAN_BYTES) continue;
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue; // fichier illisible/binaire : ignoré, jamais traité comme une preuve d'absence.
    }
    if (normalizeWhitespace(content.toLowerCase()).includes(RLS_DISABLE_PHRASE)) {
      matched.push(toRelPath(filePath));
    }
  }
  if (matched.length === 0) {
    record('rls-disable', 'PASS', 'Aucune occurrence de "DISABLE ROW LEVEL SECURITY" dans supabase/migrations/.');
  } else {
    record(
      'rls-disable',
      'WARN',
      `Occurrence(s) littérale(s) de "DISABLE ROW LEVEL SECURITY" trouvée(s) — signal pour revue security-auditor, ne conclut à aucune vulnérabilité par lui-même : ${matched.join(', ')}.`,
    );
  }
}

// ---------------------------------------------------------------------------
// D9 — SUPABASE_SERVICE_ROLE_KEY / service_role dans un périmètre client — WARN
//
// Ne scanne jamais aveuglément tout `app/` (Next.js y contient aussi du code serveur légitime) :
// le périmètre "client" est d'abord délimité (public/, *.client.*, directive top-level "use client"),
// puis seulement CE périmètre est recherché pour les motifs. Signal uniquement, ne prétend jamais
// qu'un secret est réellement exposé.
// ---------------------------------------------------------------------------

const SERVICE_ROLE_LITERALS = ['SUPABASE_SERVICE_ROLE_KEY', 'service_role'];
const CLIENT_FILENAME_RE = /\.client\.[^./\\]+$/;
// Extensions dans lesquelles une directive `'use client'` a un sens réel (convention Next.js /
// React Server Components). Une directive n'est jamais recherchée ailleurs (ex. Markdown) — corrigé
// après revue Codex (P1) : un fichier `.md` contenant un bloc de code d'exemple ne doit jamais
// compter comme une directive réelle.
const CLIENT_DIRECTIVE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts']);

// Détecte une VRAIE directive de prologue JavaScript/TypeScript `'use client'`/`"use client"`, par
// un scanner lexical CIBLÉ sur le Directive Prologue — jamais un parseur JavaScript/TypeScript
// général, jamais une expression régulière sur les premières lignes (l'ancienne approche, deux fois
// corrigée après revue Codex : elle manquait une directive précédée de commentaires, produisait des
// faux positifs sur un commentaire/une chaîne/un template littéral, puis manquait encore une
// directive suivie d'un commentaire avant sa terminaison, et acceptait à tort un littéral suivi d'un
// saut de ligne puis d'un opérateur de continuation comme `+ suffix;`).
//
// Séparation volontaire en quatre étapes (aucune ne dépasse son rôle) :
//   A. skipLeadingTrivia()        — espaces/commentaires AVANT un littéral candidat.
//   B. readStringLiteral()        — lit un littéral de chaîne isolé, ou renvoie `null`.
//   C. scanTriviaAfterLiteral()   — espaces/commentaires APRÈS le littéral, en mémorisant si un
//                                    LineTerminator a été rencontré (directement, après un
//                                    commentaire ligne, ou À L'INTÉRIEUR d'un commentaire bloc).
//   D. determineStatementTermination() — décide si le littéral termine réellement son statement :
//        1. `;` explicite (même précédé d'un commentaire) → terminé ;
//        2. fin de fichier → terminé ;
//        3. `}` → terminé (fin de bloc) ;
//        4. aucun LineTerminator rencontré et rien de ce qui précède ne termine → PAS isolé, arrêt ;
//        5. LineTerminator rencontré sans `;` → ASI, SAUF si le token significatif suivant peut
//           continuer l'expression précédente (opérateur binaire/`?.`/`.`/`[`/`(`/`` ` ``/`as`/
//           `satisfies`, etc. — §7 du rapport de correction) : dans ce cas, PAS une directive.
//
// Le prologue de directives se poursuit tant que chaque déclaration lue est un littéral de chaîne
// isolé (`'use strict'; 'use client';` reste valide) ; il s'arrête au premier vrai statement qui
// n'en est pas un (`const x = ...`, un `import`, une continuation d'expression) — jamais analysé
// au-delà, comme un moteur JavaScript traite réellement le prologue de directives.
const CONTINUATION_OPERATORS_BY_LENGTH = [
  ['===', '!==', '>>>'],
  ['**', '?.', '&&', '||', '==', '!=', '<=', '>=', '<<', '>>', '+=', '-=', '*=', '/=', '%='],
  ['+', '-', '*', '/', '%', '.', '?', '[', '(', '`', '&', '|', '^', '=', '<', '>'],
];
const CONTINUATION_KEYWORDS = ['satisfies', 'as'];

function isIdentifierChar(ch) {
  return ch !== undefined && /[A-Za-z0-9_$]/.test(ch);
}

// Un token de continuation juste après un LineTerminator signifie que le littéral précédent fait
// partie d'une expression plus large (ex. `'use client'\n+ suffix;`) — ASI ne s'applique alors pas.
function matchesContinuationToken(source, pos) {
  for (const group of CONTINUATION_OPERATORS_BY_LENGTH) {
    for (const op of group) {
      if (source.startsWith(op, pos)) return true;
    }
  }
  for (const kw of CONTINUATION_KEYWORDS) {
    if (source.startsWith(kw, pos)) {
      const before = pos > 0 ? source[pos - 1] : undefined;
      const after = source[pos + kw.length];
      if (!isIdentifierChar(before) && !isIdentifierChar(after)) return true;
    }
  }
  return false;
}

function hasUseClientDirective(source) {
  const n = source.length;
  let i = n > 0 && source.charCodeAt(0) === 0xfeff ? 1 : 0;

  // A. Trivia avant un littéral candidat — peu importe qu'un LineTerminator y apparaisse : le
  // prologue autorise des commentaires/espaces arbitraires entre deux membres.
  function skipLeadingTrivia() {
    let advanced = true;
    while (advanced) {
      advanced = false;
      while (i < n && /\s/.test(source[i])) {
        i += 1;
        advanced = true;
      }
      if (source[i] === '/' && source[i + 1] === '/') {
        i += 2;
        while (i < n && source[i] !== '\n') i += 1;
        advanced = true;
        continue;
      }
      if (source[i] === '/' && source[i + 1] === '*') {
        i += 2;
        while (i < n && !(source[i] === '*' && source[i + 1] === '/')) i += 1;
        i = Math.min(i + 2, n);
        advanced = true;
      }
    }
  }

  // B. Lit un littéral de chaîne à la position courante `i`, ou renvoie `null` si ce n'en est pas un.
  function readStringLiteral() {
    const quote = source[i];
    if (quote !== "'" && quote !== '"') return null;
    let j = i + 1;
    let value = '';
    while (j < n) {
      const ch = source[j];
      if (ch === '\\') {
        value += ch + (source[j + 1] ?? '');
        j += 2;
        continue;
      }
      if (ch === quote) return { value, end: j + 1 };
      if (ch === '\n') return null; // chaîne non terminée sur sa ligne : pas un littéral valide.
      value += ch;
      j += 1;
    }
    return null;
  }

  // C. Trivia après le littéral — mémorise tout LineTerminator rencontré, y compris à l'intérieur
  // d'un commentaire bloc multi-lignes (celui d'un commentaire ligne est traité au passage suivant,
  // quand la boucle rencontre le saut de ligne qui suit le `//`).
  function scanTriviaAfterLiteral(start) {
    let p = start;
    let sawLineTerminator = false;
    let advanced = true;
    while (advanced) {
      advanced = false;
      while (p < n && (source[p] === ' ' || source[p] === '\t')) {
        p += 1;
        advanced = true;
      }
      if (p < n && (source[p] === '\n' || source[p] === '\r')) {
        sawLineTerminator = true;
        p += 1;
        advanced = true;
        continue;
      }
      if (source[p] === '/' && source[p + 1] === '/') {
        p += 2;
        while (p < n && source[p] !== '\n') p += 1;
        advanced = true;
        continue;
      }
      if (source[p] === '/' && source[p + 1] === '*') {
        p += 2;
        while (p < n && !(source[p] === '*' && source[p + 1] === '/')) {
          if (source[p] === '\n') sawLineTerminator = true;
          p += 1;
        }
        p = Math.min(p + 2, n);
        advanced = true;
      }
    }
    return { pos: p, sawLineTerminator };
  }

  // D. Décide si le littéral lu termine réellement son statement, et où reprendre l'analyse.
  function determineStatementTermination(afterLiteralPos) {
    const { pos, sawLineTerminator } = scanTriviaAfterLiteral(afterLiteralPos);
    if (source[pos] === ';') return { terminated: true, next: pos + 1 };
    if (pos >= n) return { terminated: true, next: pos };
    if (source[pos] === '}') return { terminated: true, next: pos };
    if (!sawLineTerminator) {
      // Rien (ni `;`, ni saut de ligne) ne sépare le littéral du token suivant : pas une déclaration
      // isolée — ex. `'use client' someIdentifier` sur la même ligne.
      return { terminated: false, next: pos };
    }
    // LineTerminator rencontré sans `;` : ASI s'applique, sauf si le token suivant peut continuer
    // l'expression précédente (§7 du rapport de correction).
    if (matchesContinuationToken(source, pos)) {
      return { terminated: false, next: pos };
    }
    return { terminated: true, next: pos };
  }

  while (i < n) {
    skipLeadingTrivia();
    if (i >= n) break;

    const literal = readStringLiteral();
    if (!literal) break; // premier vrai statement non-littéral : fin du prologue de directives.

    const termination = determineStatementTermination(literal.end);
    if (!termination.terminated) break;

    if (literal.value === 'use client') return true;
    i = termination.next;
  }
  return false;
}

function isClientSurfaceFile(filePath, relPath) {
  const segments = relPath.split('/');
  if (segments[0] === 'public') return true;
  if (CLIENT_FILENAME_RE.test(path.basename(filePath))) return true;

  const ext = path.extname(filePath).toLowerCase();
  if (!CLIENT_DIRECTIVE_EXTENSIONS.has(ext)) return false;

  let content;
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_SCAN_BYTES) return false;
    content = readFileSync(filePath, 'utf8');
  } catch {
    return false;
  }
  return hasUseClientDirective(content);
}

function checkClientServiceRole(supabaseInfo) {
  if (!supabaseInfo.detected) {
    record('client-service-role', 'PASS', 'non applicable — Supabase non détecté.');
    return;
  }
  const allFiles = walkFiles(cwd, WALK_EXCLUDE_DIRS);
  const matched = [];
  for (const filePath of allFiles) {
    const relPath = toRelPath(filePath);
    if (!isClientSurfaceFile(filePath, relPath)) continue;
    let content;
    try {
      const stat = statSync(filePath);
      if (stat.size > MAX_SCAN_BYTES) continue;
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    const foundLiteral = SERVICE_ROLE_LITERALS.find((lit) => content.includes(lit));
    if (foundLiteral) {
      matched.push(`${relPath} (motif: ${foundLiteral})`);
    }
  }
  if (matched.length === 0) {
    record(
      'client-service-role',
      'PASS',
      'Aucune occurrence de SUPABASE_SERVICE_ROLE_KEY/service_role dans le périmètre client (public/, *.client.*, directive "use client").',
    );
  } else {
    record(
      'client-service-role',
      'WARN',
      `Occurrence(s) potentielle(s) dans le périmètre client — signal pour revue security-auditor, ne prouve jamais une exposition réelle : ${matched.join('; ')}.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Exécution
// ---------------------------------------------------------------------------

checkIntegrity();

const lsFilesResult = runGitLsFiles();
const statusResult = runGitStatusPorcelain();

checkAdoptionTracked(lsFilesResult);
checkCleanTree(statusResult);
checkLockfile();
checkJunkFiles(lsFilesResult);

const supabaseInfo = detectSupabase();
if (supabaseInfo.detected) {
  record('supabase', 'INFO', supabaseInfo.method === 'migrations' ? 'detected via migrations' : 'detected via dependency (@supabase/supabase-js)');
} else {
  record('supabase', 'INFO', 'not detected (neither supabase/migrations/ nor @supabase/supabase-js dependency).');
}
checkRlsDisable(supabaseInfo);
checkClientServiceRole(supabaseInfo);

// ---------------------------------------------------------------------------
// Rapport
// ---------------------------------------------------------------------------

console.log('STUDIO GUARDRAILS');
console.log('');

for (const r of results) {
  console.log(`[${r.status}] ${r.name}${r.detail ? ' — ' + r.detail : ''}`);
}

const passCount = results.filter((r) => r.status === 'PASS').length;
const blockCount = results.filter((r) => r.status === 'BLOCK').length;
const warnCount = results.filter((r) => r.status === 'WARN').length;
const infoCount = results.filter((r) => r.status === 'INFO').length;
const blocking = blockCount > 0;

console.log('');
console.log(`RESULT: ${blocking ? 'BLOCK' : 'PASS'}`);
console.log(`${results.length} checks | ${passCount} pass | ${blockCount} block | ${warnCount} warn | ${infoCount} info`);

process.exit(blocking ? 1 : 0);
