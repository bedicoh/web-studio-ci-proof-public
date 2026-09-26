#!/usr/bin/env node
// studio-verify.mjs — gabarit source, dépôt méthode web-studio-system.
//
// Commande canonique de vérification technique Web Studio, proportionnée au profil déclaré
// dans `studio.config.json` (voir docs/STUDIO_VERIFY.md pour la documentation complète).
//
// Contraintes de conception (LOT C — corrigées après revue Codex REVIEW FAIL, voir
// docs/STUDIO_VERIFY.md "Historique des corrections") :
// - Node natif uniquement : aucune dépendance npm propre à ce script.
// - Aucun réseau requis, aucune installation automatique.
// - Lecture seule sur le projet vérifié : ce script ne modifie jamais volontairement
//   le code source du projet (les commandes externes qu'il invoque — lint/typecheck/build/test —
//   peuvent, elles, écrire dans leurs répertoires habituels comme n'importe quelle exécution
//   normale de ces commandes ; ce script ne leur ajoute aucun effet de bord).
// - Ce script s'exécute depuis `process.cwd()` : il est conçu pour être copié dans un projet
//   adopté (`scripts/studio-verify.mjs`) et lancé depuis la racine de ce projet, jamais depuis
//   web-studio-system lui-même (qui ne contient pas de code applicatif — voir `README.md`).
// - Il n'orchestre que des commandes projet standards (lint/typecheck/build/test) et des
//   contrôles Web Studio génériques déjà documentés. Il n'invoque jamais, sous aucune condition,
//   les vérificateurs propres aux fixtures de gate de ce dépôt (`fixtures/**/verify.mjs`,
//   `prototypes/**/_verify.mjs`) — ce sont des artefacts synthétiques propres à un gate précis,
//   pas des contrôles génériques applicables à un projet réel.
// - Politique **fail-closed** : toute ambiguïté (config indéterminée, Git indisponible, champ
//   canonique absent/dupliqué, chemin de casse incorrecte) produit un FAIL explicite — jamais un
//   PASS implicite, et jamais un SKIP silencieux d'un contrôle par ailleurs obligatoire.
// - "Optionnel" signifie uniquement "son absence est autorisée (SKIP)" — jamais "son échec est
//   toléré". Tout statut FAIL, qu'il porte sur un contrôle obligatoire ou sur un contrôle
//   optionnel réellement exécuté, fait sortir ce script avec un code non nul.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const cwd = process.cwd();

/** @type {{ name: string, status: 'PASS'|'FAIL'|'SKIP', detail: string, required: boolean }[]} */
const results = [];

function record(name, status, detail, required) {
  results.push({ name, status, detail, required });
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Résolution de chemin stricte : existence, nature "fichier" et casse exacte.
//
// `existsSync` seul ne suffit pas : sur un système de fichiers insensible à la casse (Windows,
// macOS par défaut), `existsSync('workflow.md')` renvoie `true` même si le fichier réel s'appelle
// `WORKFLOW.md`, et `existsSync` renvoie aussi `true` pour un RÉPERTOIRE portant le nom attendu à
// la place d'un fichier. Ce helper parcourt chaque segment du chemin avec `readdirSync` et compare
// les noms exactement (sensible à la casse, quel que soit l'OS), puis vérifie que la cible finale
// est réellement un fichier (`statSync(...).isFile()`). Portable Windows/Linux/macOS.
// ---------------------------------------------------------------------------

function resolveExactFile(baseDir, relPath) {
  const segments = relPath.split('/').filter(Boolean);
  let currentDir = baseDir;
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    let entries;
    try {
      entries = readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return false;
    }
    const match = entries.find((e) => e.name === segment);
    if (!match) return false;
    const nextPath = path.join(currentDir, match.name);
    const isLast = i === segments.length - 1;
    if (isLast) {
      try {
        return statSync(nextPath).isFile();
      } catch {
        return false;
      }
    }
    if (!match.isDirectory()) return false;
    currentDir = nextPath;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Exécution des commandes projet — durci Windows, sans option `shell`, avec timeout et diagnostics.
//
// `shell: true` n'est jamais utilisé : aucune concaténation de commande, arguments toujours
// structurés (tableau), pas de risque d'injection par un nom de script. Sur POSIX, `npm` est
// invoqué directement (`spawnSync('npm', ['run', name], { shell: false })`). Sur Windows, `npm`
// est un script `.cmd`, que `spawnSync` ne peut pas exécuter directement sans `shell: true` (erreur
// EINVAL) — et `shell: true` avec des arguments en tableau est lui-même désormais déconseillé par
// Node (DEP0190 : les arguments ne sont alors que concaténés, pas échappés). Le motif sûr retenu
// ici est celui documenté par Node pour les `.cmd`/`.bat` : invoquer `cmd.exe /d /s /c` avec des
// arguments structurés, sans jamais passer par l'option `shell`. `scriptName` provient toujours
// d'une liste fixe interne (`lint`/`typecheck`/`test`/`build`), jamais d'une entrée externe.
// Timeout choisi pour la V1 : 10 minutes maximum par commande projet. Sur échec (spawn impossible,
// signal, timeout, ou code de sortie non nul), le diagnostic restitué inclut le nom de la commande,
// le code/signal/timeout, et un extrait de stderr (ou stdout à défaut) tronqué pour éviter de
// déverser une sortie gigantesque dans le rapport.
// ---------------------------------------------------------------------------

const COMMAND_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes maximum par commande projet (choix V1).
const OUTPUT_TRUNCATE_CHARS = 4000;

function truncateOutput(text) {
  const t = (text || '').trim();
  if (t.length <= OUTPUT_TRUNCATE_CHARS) return t;
  return `${t.slice(0, OUTPUT_TRUNCATE_CHARS)}\n… [tronqué, ${t.length - OUTPUT_TRUNCATE_CHARS} caractère(s) supplémentaire(s)]`;
}

function runNpmRun(label, scriptName) {
  const isWindows = process.platform === 'win32';
  const command = isWindows ? 'cmd.exe' : 'npm';
  const args = isWindows ? ['/d', '/s', '/c', 'npm', 'run', scriptName] : ['run', scriptName];

  const startedAt = Date.now();
  const res = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    shell: false,
    timeout: COMMAND_TIMEOUT_MS,
  });
  const elapsedMs = Date.now() - startedAt;
  const likelyTimedOut = elapsedMs >= COMMAND_TIMEOUT_MS - 250;

  if (res.error) {
    if (likelyTimedOut) {
      return { ok: false, detail: `"${label}" a dépassé le délai maximal (${Math.round(COMMAND_TIMEOUT_MS / 60000)} min).` };
    }
    return { ok: false, detail: `échec du lancement de "${label}" : ${res.error.message}` };
  }
  if (res.signal) {
    const reason = likelyTimedOut
      ? `dépassement du délai maximal (${Math.round(COMMAND_TIMEOUT_MS / 60000)} min)`
      : `signal ${res.signal}`;
    return { ok: false, detail: `"${label}" interrompu (${reason}).` };
  }
  if (res.status === 0) {
    return { ok: true, detail: `"${label}" a réussi (code 0).` };
  }
  const stderr = truncateOutput(res.stderr);
  const stdout = truncateOutput(res.stdout);
  const parts = [`code ${res.status}`];
  if (stderr) parts.push(`stderr: ${stderr}`);
  if (!stderr && stdout) parts.push(`stdout: ${stdout}`);
  return { ok: false, detail: `"${label}" a échoué (${parts.join(' — ')}).` };
}

// ---------------------------------------------------------------------------
// 0. Configuration — studio.config.json (source de vérité MACHINE, voir docs/STUDIO_VERIFY.md)
//
// Fail-closed explicite : le résultat du parsing est porté par un objet { ok, value, error },
// jamais par `null` comme sentinelle ambiguë entre "parsing échoué" et "JSON valide égal à null".
// Un fichier contenant littéralement `null`, un tableau, une chaîne, un nombre, ou un objet
// incomplet produit un FAIL explicite — jamais un contrôle silencieusement absent du rapport.
// ---------------------------------------------------------------------------

function loadStudioConfig() {
  if (!resolveExactFile(cwd, 'studio.config.json')) {
    return { ok: false, error: 'studio.config.json introuvable à la racine du projet (absent, répertoire, ou casse incorrecte).' };
  }
  const configPath = path.join(cwd, 'studio.config.json');
  let raw;
  try {
    raw = readFileSync(configPath, 'utf8');
  } catch (err) {
    return { ok: false, error: `studio.config.json illisible : ${err.message}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, error: `studio.config.json n'est pas un JSON valide : ${err.message}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      ok: false,
      error: `studio.config.json doit être un objet JSON (ni null, ni tableau, ni valeur scalaire) — trouvé : ${JSON.stringify(parsed)}.`,
    };
  }
  if (parsed.schemaVersion !== 1) {
    return { ok: false, error: `schemaVersion attendu : 1 — trouvé : ${JSON.stringify(parsed.schemaVersion)}.` };
  }
  if (parsed.profile !== 'A' && parsed.profile !== 'B' && parsed.profile !== 'C') {
    return { ok: false, error: `profile attendu : "A" | "B" | "C" — trouvé : ${JSON.stringify(parsed.profile)}.` };
  }
  if (typeof parsed.publicInterface !== 'boolean') {
    return { ok: false, error: `publicInterface attendu : booléen strict — trouvé : ${JSON.stringify(parsed.publicInterface)}.` };
  }
  return { ok: true, value: parsed };
}

const configResult = loadStudioConfig();
const configValid = configResult.ok;
const config = configValid ? configResult.value : null;

if (configValid) {
  record('config', 'PASS', `profile=${config.profile}, publicInterface=${config.publicInterface}.`, true);
} else {
  record('config', 'FAIL', configResult.error, true);
}

const profile = configValid ? config.profile : null;
const publicInterface = configValid ? config.publicInterface : null;

// ---------------------------------------------------------------------------
// 1. Fichiers d'adoption obligatoires (docs/PROJECT_ADOPTION.md §3 et §3.1)
//
// Liste limitée aux supports :
//   (a) marqués « obligatoire » ET « tous » profils dans le tableau §3,
//   (b) listés comme « disponibles dès l'adoption » en §3.1 (pas générés plus tard par une
//       étape du workflow, ex. docs/PROJECT_BRIEF.md ou docs/design/DESIGN_DECISIONS.md, qui
//       ont leur propre contrôle dédié ci-dessous),
//   (c) dont la condition (obligatoire « si interface publique ») est déjà modélisée par
//       `studio.config.json` (`publicInterface`).
//
// Volontairement exclus : les supports conditionnés à l'usage d'un mécanisme ou d'un skill
// précis (ex. « obligatoire pour utiliser ce rôle dans Claude Code/Codex ») — cette condition
// n'est modélisée par aucun champ de `studio.config.json` en V1, et une présomption univoque
// serait une invention, pas une lecture fidèle de PROJECT_ADOPTION.md.
//
// Cinq entrées ajoutées après revue Codex (elles étaient omises à tort) : leur condition dans
// PROJECT_ADOPTION.md §3 ("dès que tel standard est adopté") se résout à TOUJOURS vraie, parce que
// le standard déclencheur correspondant est lui-même déjà de manière inconditionnelle dans cette
// même liste ADOPTION_FILES_ALWAYS — ce n'est pas une invention, c'est la conséquence logique de
// la doctrine déjà appliquée par ce script :
//   - THIRD_PARTY_NOTICES.md : obligatoire si le standard frontend craft OU sécurité/maintenabilité
//     est adopté (§3, ligne « Notices tierces ») — ces trois standards sont déjà toujours requis
//     ci-dessous (FRONTEND_CRAFT_STANDARD.md, SECURITY_ENGINEERING_STANDARD.md,
//     MAINTAINABILITY_STANDARD.md).
//   - docs/EMIL_SKILLS_ADAPTATION.md : obligatoire dès que le standard frontend craft (ou une
//     portion adaptée) est adopté (§3, ligne « Adaptation emilkowalski/skills ») — même raison.
//   - docs/ECC_SECURITY_ADAPTATION.md : obligatoire dès que les standards sécurité/maintenabilité
//     (ou une portion adaptée) sont adoptés (§3, ligne « Adaptation affaan-m/ECC ») — même raison.
//   - scripts/studio-verify.mjs et docs/STUDIO_VERIFY.md : obligatoires « pour utiliser
//     npm run studio:verify » (§3, lignes correspondantes) — condition toujours vraie ici,
//     puisque ce script EST studio-verify.mjs en cours d'exécution.
// Voir docs/STUDIO_VERIFY.md pour le détail de ce raisonnement et sa portée.
// ---------------------------------------------------------------------------

const ADOPTION_FILES_ALWAYS = [
  'WORKFLOW.md',
  'CLAUDE.md',
  'AGENTS.md',
  'THIRD_PARTY_NOTICES.md',
  'scripts/studio-verify.mjs',
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
];

const ADOPTION_FILES_PUBLIC_INTERFACE = [
  'docs/DESIGN_ANTI_GENERIC_STANDARD.md',
  'docs/checklists/DESIGN_IDENTITY_AUDIT.md',
  'docs/DESIGN_HANDOFF_STANDARD.md',
];

{
  const required = [...ADOPTION_FILES_ALWAYS];
  if (configValid && publicInterface) required.push(...ADOPTION_FILES_PUBLIC_INTERFACE);
  const missing = required.filter((f) => !resolveExactFile(cwd, f));
  if (missing.length === 0) {
    const note = configValid
      ? ''
      : ' (fichiers conditionnés à publicInterface non contrôlés — config invalide, voir "config" ci-dessus)';
    record('adoption files', 'PASS', `${required.length} fichier(s) obligatoire(s) présent(s), casse exacte vérifiée${note}.`, true);
  } else {
    record(
      'adoption files',
      'FAIL',
      `Fichier(s) obligatoire(s) manquant(s), absent(s), remplacé(s) par un répertoire, ou casse incorrecte : ${missing.join(', ')}.`,
      true,
    );
  }
}

// ---------------------------------------------------------------------------
// 2. Commandes projet — lint / typecheck / test / build
//
// Profils A, B et C : lint/typecheck/build REQUIRED, test OPTIONAL (docs/WEB_STUDIO_V1_SPEC.md
// §4 ; MAINTAINABILITY_STANDARD.md §13). "OPTIONAL" signifie uniquement que son ABSENCE est
// autorisée (SKIP) — jamais que sa présence invalide ou son échec d'exécution soit toléré : un
// script présent mais vide/non-string, ou une commande qui échoue, produit un FAIL qu'il soit
// REQUIRED ou OPTIONAL (voir l'agrégateur global en fin de fichier).
// ---------------------------------------------------------------------------

function checkProjectScript(name, required) {
  if (!resolveExactFile(cwd, 'package.json')) {
    if (required) {
      record(name, 'FAIL', `package.json introuvable (ou casse incorrecte) — commande "${name}" requise par le profil ${profile ?? '?'}.`, true);
    } else {
      record(name, 'SKIP', 'package.json introuvable — commande optionnelle non déclarée.', false);
    }
    return;
  }

  let pkg;
  try {
    pkg = JSON.parse(readFileSync(path.join(cwd, 'package.json'), 'utf8'));
  } catch (err) {
    record(name, 'FAIL', `package.json n'est pas un JSON valide : ${err.message}`, required);
    return;
  }
  // pkg.scripts sur un JSON valide mais non-objet (null, tableau, chaîne, nombre) lèverait une
  // exception non interceptée — la même politique fail-closed que le reste du script s'applique :
  // un FAIL contrôlé, jamais un plantage brut du processus.
  if (pkg === null || typeof pkg !== 'object' || Array.isArray(pkg)) {
    record(name, 'FAIL', `package.json doit être un objet JSON (ni null, ni tableau, ni valeur scalaire) — trouvé : ${JSON.stringify(pkg)}.`, required);
    return;
  }

  const scripts = pkg.scripts;
  const scriptsIsCleanObject = scripts !== null && typeof scripts === 'object' && !Array.isArray(scripts);
  const hasOwn = scriptsIsCleanObject && Object.prototype.hasOwnProperty.call(scripts, name);

  if (!hasOwn) {
    if (required) {
      record(name, 'FAIL', `script "${name}" requis par le profil ${profile ?? '?'}, absent de package.json.`, true);
    } else {
      record(name, 'SKIP', 'commande optionnelle non déclarée dans package.json.', false);
    }
    return;
  }

  const rawValue = scripts[name];
  const validValue = typeof rawValue === 'string' && rawValue.trim() !== '';
  if (!validValue) {
    record(
      name,
      'FAIL',
      `script "${name}" présent dans package.json mais invalide (chaîne non vide attendue — trouvé : ${JSON.stringify(rawValue)}).`,
      required,
    );
    return;
  }

  const run = runNpmRun(`npm run ${name}`, name);
  record(name, run.ok ? 'PASS' : 'FAIL', run.detail, required);
}

checkProjectScript('lint', true);
checkProjectScript('typecheck', true);
checkProjectScript('test', false);
checkProjectScript('build', true);

// ---------------------------------------------------------------------------
// 3. Suivi Git des fichiers d'environnement sensibles — REQUIRED, fail-closed
//
// Contrôle générique unique (docs/SECURITY_ENGINEERING_STANDARD.md §2) : aucun fichier .env réel
// ne doit être suivi par Git. `.env.example` / `.env.sample` restent autorisés — comparaison par
// nom de fichier exact (`path.basename`, donc y compris en sous-dossier), jamais par préfixe ni
// par contenu. Aucune lecture de valeur de variable, aucun scanner de secret.
//
// Ce contrôle est REQUIRED : si Git est indisponible, si `git ls-files` échoue, ou si le
// répertoire courant n'est pas un dépôt Git exploitable, le résultat est un FAIL explicite —
// jamais un SKIP. Un SKIP aurait laissé passer silencieusement un projet sans protection Git
// vérifiable (comportement fail-open corrigé après revue Codex).
// ---------------------------------------------------------------------------

{
  const FORBIDDEN_ENV_FILENAMES = new Set(['.env', '.env.local', '.env.production', '.env.development', '.env.test']);

  const res = spawnSync('git', ['ls-files'], { cwd, encoding: 'utf8', shell: false, timeout: COMMAND_TIMEOUT_MS });

  if (res.error) {
    record('env tracking', 'FAIL', `Git indisponible ici : ${res.error.message} — contrôle obligatoire, fail-closed (pas de SKIP).`, true);
  } else if (res.status !== 0) {
    const stderr = truncateOutput(res.stderr);
    record(
      'env tracking',
      'FAIL',
      `"git ls-files" a échoué (code ${res.status}${stderr ? ` — ${stderr}` : ''}) — dépôt Git non exploitable ici ; contrôle obligatoire, fail-closed.`,
      true,
    );
  } else {
    const files = (res.stdout || '').split('\n').map((l) => l.trim()).filter(Boolean);
    const flagged = files.filter((f) => FORBIDDEN_ENV_FILENAMES.has(path.basename(f)));
    if (flagged.length === 0) {
      record('env tracking', 'PASS', 'Aucun fichier .env sensible suivi par Git (.env.example / .env.sample restent autorisés, y compris en sous-dossier).', true);
    } else {
      record('env tracking', 'FAIL', `Fichier(s) d'environnement suivi(s) par Git : ${flagged.join(', ')}.`, true);
    }
  }
}

// ---------------------------------------------------------------------------
// 4. Direction de design approuvée (docs/DESIGN_HANDOFF_STANDARD.md §1.2, §4)
//
// Uniquement lorsque publicInterface=true. Parsing STRUCTUREL, pas une simple recherche de la
// première occurrence de "Statut : approuvé" dans tout le document (falsifiable par un exemple
// ailleurs dans le texte, ou par un champ dupliqué) :
//   - le contenu des blocs de code (``` ... ``` et ~~~ ... ~~~) est neutralisé avant toute
//     recherche de titre/champ (stripFencedCodeBlocks) : un exemple Markdown documenté dans un
//     bloc de code ne doit jamais compter comme structure canonique réelle ;
//   - le titre "## 1. Identification" doit apparaître EXACTEMENT une fois dans le document (hors
//     blocs de code) — une section dupliquée est une ambiguïté structurelle, refusée (FAIL), pas
//     résolue silencieusement en retenant la première occurrence ; même règle pour
//     "## 16. Approbation" ;
//   - le champ canonique "Statut" est lu UNIQUEMENT dans la section "## 1. Identification"
//     (templates/DESIGN_DECISIONS_TEMPLATE.md) ; il doit apparaître exactement une fois dans
//     cette section, sans quoi le contrôle échoue (absence ou ambiguïté) ;
//   - les champs canoniques "Approbateur humain" et "Date d'approbation" sont lus UNIQUEMENT dans
//     la section "## 16. Approbation" ; chacun doit apparaître exactement une fois et être non vide.
// Une mention "Statut : approuvé" ailleurs dans le document (exemple, historique, texte libre, ou
// bloc de code) ne suffit jamais : elle est hors de la section 1 (ou neutralisée) et donc ignorée
// par construction.
//
// LIMITE EXPLICITE : ce contrôle vérifie uniquement que la PREUVE DOCUMENTAIRE canonique est
// structurée correctement (champs présents, uniques, non vides, statut exact). Il ne prouve pas,
// et ne prétend pas prouver, qu'une approbation humaine a réellement eu lieu — cette garantie reste
// hors de portée d'un contrôle mécanique et relève de la revue indépendante (docs/AGENT_USAGE.md §3).
// ---------------------------------------------------------------------------

// Neutralise le contenu des blocs de code délimités (``` ... ``` et ~~~ ... ~~~) avant toute
// recherche de titre ou de champ canonique : un exemple Markdown documenté à l'intérieur d'un bloc
// de code (ex. un extrait illustrant la convention "## 1. Identification" / "- Statut : approuvé")
// ne doit jamais être confondu avec la structure réelle du document. Les lignes à l'intérieur d'un
// bloc sont vidées (jamais supprimées, pour garder la même numérotation de ligne) ; la ligne de
// balise elle-même est également vidée. Gère la simple imbrication ``` à l'intérieur de ~~~ (ou
// l'inverse) : un bloc ne se referme que sur une balise du même caractère et d'au moins la même
// longueur, conformément à CommonMark — une balise de l'autre caractère rencontrée à l'intérieur
// reste neutralisée comme le reste du contenu du bloc, jamais interprétée comme fermeture.
function stripFencedCodeBlocks(text) {
  const lines = text.split(/\r\n|\n/);
  const result = new Array(lines.length);
  let fenceChar = null;
  let fenceLen = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Groupe 2 capture tout ce qui suit la séquence de fence sur la ligne (info string à
    // l'ouverture, ou suffixe éventuel sur une ligne qui prétend fermer).
    const m = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (m) {
      const marker = m[1];
      const rest = m[2];
      const char = marker[0];
      const len = marker.length;
      if (fenceChar === null) {
        // Ouverture : un info string après la fence est autorisé sans condition sur son contenu
        // (ex. ```md, ~~~text) — seule la FERMETURE est contrainte (voir ci-dessous, §1 du rapport
        // de correction). Ne pas confondre la règle de fermeture avec une interdiction d'info
        // string à l'ouverture.
        fenceChar = char;
        fenceLen = len;
        result[i] = '';
        continue;
      }
      // Fermeture valide seulement si : même caractère, longueur >= celle de l'ouverture, ET rien
      // d'autre que des espaces/tabs après la séquence de fermeture. Une ligne comme
      // "~~~not-a-close" COMMENCE par une séquence de fence suffisante mais n'est PAS une fermeture
      // — accepter uniquement le préfixe (ancienne logique, corrigée ici) laissait réactiver
      // prématurément du contenu encore situé dans le bloc Markdown.
      const isValidClose = char === fenceChar && len >= fenceLen && /^[ \t]*$/.test(rest);
      if (isValidClose) {
        fenceChar = null;
        fenceLen = 0;
        result[i] = '';
        continue;
      }
    }
    result[i] = fenceChar !== null ? '' : line;
  }
  return result.join('\n');
}

// Retourne le texte de la section trouvée UNIQUEMENT si le titre canonique apparaît exactement une
// fois dans le document (hors blocs de code, déjà neutralisés par l'appelant) : une section dupliquée
// est une ambiguïté structurelle, traitée fail-closed comme un champ dupliqué (§0 bis), jamais
// résolue silencieusement en retenant la première occurrence.
function extractSection(text, headingRegex) {
  const lines = text.split(/\r\n|\n/);
  const matchIndexes = [];
  for (let i = 0; i < lines.length; i++) {
    if (headingRegex.test(lines[i])) matchIndexes.push(i);
  }
  if (matchIndexes.length === 0) return { found: 0, text: null };
  if (matchIndexes.length > 1) return { found: matchIndexes.length, text: null };

  const start = matchIndexes[0] + 1;
  let end = lines.length;
  for (let j = start; j < lines.length; j++) {
    if (/^##\s+/.test(lines[j])) {
      end = j;
      break;
    }
  }
  return { found: 1, text: lines.slice(start, end).join('\n') };
}

function extractCanonicalField(sectionText, label) {
  // Espacement intra-ligne uniquement ([ \t], jamais \s) : `\s` inclut le saut de ligne, ce qui
  // ferait déborder `(.*)$` sur la ligne suivante lorsque le champ est vide (ex. "- Statut :" suivi
  // d'un retour à la ligne) et capturerait à tort le contenu de la ligne suivante comme valeur.
  const re = new RegExp(`^-[ \\t]*${escapeRegExp(label)}[ \\t]*:[ \\t]*(.*)$`, 'gm');
  return [...sectionText.matchAll(re)];
}

{
  if (!configValid) {
    record('design decision', 'SKIP', 'publicInterface indéterminé (config invalide, voir "config" ci-dessus).', true);
  } else if (!publicInterface) {
    record('design decision', 'SKIP', 'non applicable (publicInterface=false).', true);
  } else if (!resolveExactFile(cwd, 'docs/design/DESIGN_DECISIONS.md')) {
    record('design decision', 'FAIL', 'docs/design/DESIGN_DECISIONS.md absent, remplacé par un répertoire, ou casse incorrecte (obligatoire si publicInterface=true).', true);
  } else {
    let text = null;
    try {
      text = readFileSync(path.join(cwd, 'docs', 'design', 'DESIGN_DECISIONS.md'), 'utf8');
    } catch (err) {
      record('design decision', 'FAIL', `docs/design/DESIGN_DECISIONS.md illisible : ${err.message}`, true);
    }
    if (text !== null) {
      // Les blocs de code (exemples Markdown documentés dans le fichier) sont neutralisés avant
      // toute recherche de titre/champ : voir stripFencedCodeBlocks ci-dessus.
      const sanitized = stripFencedCodeBlocks(text);
      const section1 = extractSection(sanitized, /^##\s*1\.\s*Identification\b/);
      const section16 = extractSection(sanitized, /^##\s*16\.\s*Approbation\b/);

      if (section1.found === 0) {
        record('design decision', 'FAIL', 'Section canonique "## 1. Identification" absente de docs/design/DESIGN_DECISIONS.md (hors blocs de code).', true);
      } else if (section1.found > 1) {
        record('design decision', 'FAIL', `Section canonique "## 1. Identification" dupliquée (trouvée ${section1.found} fois hors blocs de code) — ambiguïté, contrôle refusé.`, true);
      } else if (section16.found === 0) {
        record('design decision', 'FAIL', 'Section canonique "## 16. Approbation" absente de docs/design/DESIGN_DECISIONS.md (hors blocs de code).', true);
      } else if (section16.found > 1) {
        record('design decision', 'FAIL', `Section canonique "## 16. Approbation" dupliquée (trouvée ${section16.found} fois hors blocs de code) — ambiguïté, contrôle refusé.`, true);
      } else {
        const statutMatches = extractCanonicalField(section1.text, 'Statut');
        const approbateurMatches = extractCanonicalField(section16.text, 'Approbateur humain');
        const dateMatches = extractCanonicalField(section16.text, "Date d'approbation");

        if (statutMatches.length !== 1) {
          record('design decision', 'FAIL', `Champ canonique "Statut" absent ou dupliqué dans la section 1 (trouvé ${statutMatches.length} occurrence(s)).`, true);
        } else if (statutMatches[0][1].trim() !== 'approuvé') {
          record(
            'design decision',
            'FAIL',
            `Statut canonique="${statutMatches[0][1].trim() || '(vide)'}" (attendu : "approuvé", section 1 uniquement — une mention ailleurs dans le document ne compte pas).`,
            true,
          );
        } else if (approbateurMatches.length !== 1) {
          record('design decision', 'FAIL', `Champ canonique "Approbateur humain" absent ou dupliqué dans la section 16 (trouvé ${approbateurMatches.length} occurrence(s)).`, true);
        } else if (approbateurMatches[0][1].trim() === '') {
          record('design decision', 'FAIL', 'Champ canonique "Approbateur humain" présent mais vide dans la section 16.', true);
        } else if (dateMatches.length !== 1) {
          record('design decision', 'FAIL', `Champ canonique "Date d'approbation" absent ou dupliqué dans la section 16 (trouvé ${dateMatches.length} occurrence(s)).`, true);
        } else if (dateMatches[0][1].trim() === '') {
          record('design decision', 'FAIL', "Champ canonique \"Date d'approbation\" présent mais vide dans la section 16.", true);
        } else {
          record(
            'design decision',
            'PASS',
            'docs/design/DESIGN_DECISIONS.md — statut="approuvé", approbateur humain et date d\'approbation renseignés (section 16). Preuve documentaire structurée uniquement — ne certifie pas qu\'une approbation humaine a réellement eu lieu.',
            true,
          );
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Rapport
// ---------------------------------------------------------------------------

console.log('STUDIO VERIFY');
console.log(`Profile: ${configValid ? profile : '(indéterminé)'}`);
console.log('');

for (const r of results) {
  console.log(`[${r.status}] ${r.name}${r.detail ? ' — ' + r.detail : ''}`);
}

const passCount = results.filter((r) => r.status === 'PASS').length;
const skipCount = results.filter((r) => r.status === 'SKIP').length;
const failCount = results.filter((r) => r.status === 'FAIL').length;

// Tout FAIL bloque, qu'il porte sur un contrôle REQUIRED ou sur un contrôle OPTIONAL réellement
// exécuté : "optionnel" ne signifie que "absence autorisée" (SKIP), jamais "échec toléré".
const blockingFail = results.some((r) => r.status === 'FAIL');

console.log('');
console.log(`RESULT: ${blockingFail ? 'FAIL' : 'PASS'}`);
console.log(`${results.length} checks | ${passCount} pass | ${skipCount} skip | ${failCount} fail`);

process.exit(blockingFail ? 1 : 0);
