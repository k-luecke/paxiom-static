// Zero-dependency ESM -> CommonJS + dual TypeScript declaration (.d.mts / .d.cts) builder.
// Ensures @paxiom/receipts works identically under ESM (`import`) and Node >=18 CommonJS (`require`),
// including TypeScript `"module": "nodenext"` projects without `"type": "module"` (e.g. @coinbase/agentkit).

import { mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/\/+$/, '');
const SRC_DIR = join(ROOT, 'src');
const CJS_DIR = join(ROOT, 'cjs');
const CHECK_ONLY = process.argv.includes('--check');

function rewriteSpec(spec) {
  return spec.endsWith('.mjs') ? spec.slice(0, -4) + '.cjs' : spec;
}

function parseBindingList(rawList) {
  return rawList
    .split(',')
    .map((part) => part.replace(/\/\/.*$/gm, '').trim())
    .filter(Boolean)
    .map((item) => {
      const m = item.match(/^([A-Za-z0-9_$]+)(?:\s+as\s+([A-Za-z0-9_$]+))?$/);
      if (!m) throw new Error(`Unsupported import/export specifier: "${item}"`);
      return { imported: m[1], local: m[2] || m[1] };
    });
}

function transpileMjsToCjs(source, filename) {
  let code = source.replace(/\r\n/g, '\n');
  let reExportIdx = 0;
  const directExports = [];
  const lazyReExports = [];

  // 1. Named imports: import { a, b as c } from '...';
  code = code.replace(
    /^import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"];?/gm,
    (_, list, spec) => {
      const bindings = parseBindingList(list);
      const mapped = bindings
        .map(({ imported, local }) => (imported === local ? imported : `${imported}: ${local}`))
        .join(', ');
      return `const { ${mapped} } = require('${rewriteSpec(spec)}');`;
    }
  );

  // 2. Default imports: import x from '...';
  code = code.replace(
    /^import\s+([A-Za-z0-9_$]+)\s+from\s*['"]([^'"]+)['"];?/gm,
    (_, ident, spec) => `const ${ident} = require('${rewriteSpec(spec)}');`
  );

  // 3. Re-exports from another module: export { a, b as c } from '...';
  // Emit require() + lazy enumerable getters AFTER all local exports.* assignments in footer
  // so circular graphs (web.cjs <-> guard.cjs) resolve cleanly in EVERY require() order.
  code = code.replace(
    /^export\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"];?/gm,
    (_, list, spec) => {
      const modVar = `_reexport_${++reExportIdx}`;
      const bindings = parseBindingList(list);
      lazyReExports.push(`const ${modVar} = require('${rewriteSpec(spec)}');`);
      for (const { imported, local } of bindings) {
        lazyReExports.push(
          `Object.defineProperty(exports, '${local}', { enumerable: true, get: function () { return ${modVar}.${imported}; } });`
        );
      }
      return '';
    }
  );

  // 4. Local named export list: export { a, b as c };
  code = code.replace(/^export\s*\{([^}]*)\};?/gm, (_, list) => {
    const bindings = parseBindingList(list);
    for (const { imported, local } of bindings) {
      directExports.push({ local: imported, exported: local });
    }
    return '';
  });

  // 5. Export declarations: export const/let/function/async function ...
  code = code.replace(
    /^export\s+(async\s+function|function|const|let)\s+([A-Za-z0-9_$]+)/gm,
    (_, declKind, name) => {
      directExports.push({ local: name, exported: name });
      return `${declKind} ${name}`;
    }
  );

  if (/^(?:import|export)\b/m.test(code)) {
    throw new Error(`Unhandled ESM import/export syntax remaining in ${filename}`);
  }

  if (filename === 'web.mjs' || filename === 'proofs.mjs') {
    code = code.replace(
      'const c = explicitCrypto || globalThis.crypto;',
      "const c = explicitCrypto || globalThis.crypto || require('node:crypto').webcrypto;"
    );
  }

  const footer = [];
  for (const { local, exported } of directExports) {
    footer.push(`exports.${exported} = ${local};`);
  }
  footer.push(...lazyReExports);

  return `'use strict';\n// Auto-generated from src/${filename} by scripts/build-cjs.mjs — do not edit directly.\n${code.trimEnd()}\n\n${footer.join('\n')}\n`;
}

function toDcts(dtsContent) {
  return dtsContent
    .replace(/\r\n/g, '\n')
    .replace(/from\s+(['"])(\.[^'"]+?)\.mjs\1/g, 'from $1$2.cjs$1');
}

const expectedFiles = new Map();

// Build .cjs from every src/*.mjs
for (const entry of readdirSync(SRC_DIR).sort()) {
  if (!entry.endsWith('.mjs')) continue;
  const srcPath = join(SRC_DIR, entry);
  const srcText = readFileSync(srcPath, 'utf8');
  const cjsName = entry.slice(0, -4) + '.cjs';
  expectedFiles.set(join(CJS_DIR, cjsName), transpileMjsToCjs(srcText, entry));
}

// Build src/*.d.mts and cjs/*.d.cts from src/*.d.ts
for (const entry of readdirSync(SRC_DIR).sort()) {
  if (!entry.endsWith('.d.ts')) continue;
  const srcPath = join(SRC_DIR, entry);
  const dtsText = readFileSync(srcPath, 'utf8').replace(/\r\n/g, '\n');
  const base = entry.slice(0, -5);
  expectedFiles.set(join(SRC_DIR, `${base}.d.mts`), dtsText);
  expectedFiles.set(join(CJS_DIR, `${base}.d.cts`), toDcts(dtsText));
}

if (CHECK_ONLY) {
  let drift = 0;
  for (const [outPath, want] of expectedFiles.entries()) {
    if (!existsSync(outPath) || readFileSync(outPath, 'utf8') !== want) {
      console.error(`FAIL  out-of-date generated artifact: ${outPath}`);
      drift++;
    }
  }
  if (drift > 0) {
    console.error(`Run "node ./scripts/build-cjs.mjs" to regenerate CommonJS & TypeScript artifacts.`);
    process.exit(1);
  }
  console.log(`PASS  all ${expectedFiles.size} CommonJS (.cjs/.d.cts) & .d.mts artifacts match src/`);
} else {
  mkdirSync(CJS_DIR, { recursive: true });
  for (const [outPath, want] of expectedFiles.entries()) {
    writeFileSync(outPath, want, 'utf8');
  }
  console.log(`Built ${expectedFiles.size} CommonJS (.cjs/.d.cts) & .d.mts artifacts.`);
}
