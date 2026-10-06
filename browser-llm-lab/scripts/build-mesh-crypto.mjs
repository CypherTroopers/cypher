// Rebuild offline after npm ci. Runtime never contacts npm or a CDN.
import { build } from 'esbuild';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const root = new URL('../', import.meta.url);
const output = new URL('public/vendor/', root);
await mkdir(output, { recursive: true });
const packages = ['@noble/curves', '@noble/hashes'];
let licenses = '';
const dependencies = [];
for (const name of packages) {
  const pkg = JSON.parse(await readFile(new URL(`node_modules/${name}/package.json`, root)));
  dependencies.push({ name, version: pkg.version, license: pkg.license, repository: pkg.repository?.url || pkg.repository });
  licenses += `${name} ${pkg.version}\n${await readFile(new URL(`node_modules/${name}/LICENSE`, root), 'utf8')}\n`;
}
const result = await build({ stdin: { contents: "export { secp256k1 } from '@noble/curves/secp256k1.js'; export { keccak_256 } from '@noble/hashes/sha3.js';", resolveDir: root.pathname },
  bundle: true, write: false, format: 'esm', platform: 'browser', target: ['es2022'], minify: true, legalComments: 'inline',
  banner: { js: `/*\n${licenses.replaceAll('*/', '* /')}*/` } });
const bytes = result.outputFiles[0].contents;
await writeFile(new URL('mesh-crypto.js', output), bytes);
const provenance = { build: 'npm ci && npm run build:mesh-crypto', bundler: JSON.parse(await readFile(new URL('node_modules/esbuild/package.json', root))).version,
  artifact: 'mesh-crypto.js', sha256: createHash('sha256').update(bytes).digest('hex'), packages: dependencies };
await writeFile(new URL('mesh-crypto-LICENSE.txt', output), licenses);
await writeFile(new URL('mesh-crypto-provenance.json', output), JSON.stringify(provenance, null, 2) + '\n');
