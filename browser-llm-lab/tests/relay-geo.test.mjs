import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { countryCentroid } from '../relay/geo.mjs';

test('country coverage includes previously omitted continents and regional neighbors', () => {
  for (const code of ['DK', 'SE', 'NO', 'AT', 'BE', 'PL', 'PT', 'GR', 'CN', 'TH', 'VN', 'ID', 'PH', 'MY', 'NZ', 'MX', 'AR', 'ZA', 'NG', 'EG', 'AE']) {
    assert.equal(countryCentroid(code)?.countryCode, code, `${code} should have a sourced country anchor`);
  }
});

test('published country anchors preserve coordinate direction and country accuracy', () => {
  assert.deepEqual(countryCentroid('JP'), { countryCode: 'JP', label: 'Japan', lat: 36.20, lon: 138.25, accuracy: 'country', source: 'cloudflare' });
  assert.deepEqual(countryCentroid('TH'), { countryCode: 'TH', label: 'Thailand', lat: 15.87, lon: 100.99, accuracy: 'country', source: 'cloudflare' });
  const south = countryCentroid('NZ'); assert.ok(south.lat < 0 && south.lon > 0);
  const west = countryCentroid('MX'); assert.ok(west.lat > 0 && west.lon < 0);
});

test('sourced newer territory entries do not inherit a parent country position', () => {
  for (const code of ['AX', 'BL', 'CW', 'MF', 'SS', 'SX', 'UM']) assert.equal(countryCentroid(code)?.countryCode, code);
  assert.equal(countryCentroid('SS').lat, 7.23); assert.equal(countryCentroid('SS').lon, 30.39);
  assert.equal(countryCentroid('CW').lat, 12.15); assert.equal(countryCentroid('CW').lon, -68.92);
  assert.notDeepEqual(countryCentroid('CW'), countryCentroid('NL'));
});

test('missing, Tor, retired, unsupported and malformed codes never fabricate coordinates', () => {
  for (const code of [undefined, null, '', 'XX', 'T1', 'BQ', 'AN', 'GZ', 'ZZ', 'EU', 'jp', ' JP', 'JP ', 'JP,US', 'JP\n', 'constructor', '__proto__', 0, ['JP'], {}]) {
    assert.equal(countryCentroid(code), null, `Unexpected location for ${JSON.stringify(code)}`);
  }
});

test('all returned anchors are bounded and contain only shared country metadata', () => {
  let count = 0;
  for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
    const code = String.fromCharCode(a, b), result = countryCentroid(code); if (!result) continue;
    count++;
    assert.deepEqual(Object.keys(result).sort(), ['accuracy', 'countryCode', 'label', 'lat', 'lon', 'source']);
    assert.equal(result.countryCode, code); assert.equal(result.accuracy, 'country');
    assert.ok(Number.isFinite(result.lat) && Math.abs(result.lat) <= 90);
    assert.ok(Number.isFinite(result.lon) && Math.abs(result.lon) <= 180);
    assert.ok(typeof result.label === 'string' && result.label.length > 0 && result.label.length < 100);
  }
  assert.equal(count, 249);
});

test('one caller cannot change the shared anchor returned for another participant', () => {
  const first = countryCentroid('DK'); first.lat = 0; first.label = 'changed';
  assert.equal(countryCentroid('DK').lat, 56.26); assert.equal(countryCentroid('DK').label, 'Denmark');
});

test('country-data provenance records source licenses, byte hashes and deliberate unknowns', async () => {
  const metadata = JSON.parse(await readFile(new URL('../relay/geo-data-sources.json', import.meta.url)));
  assert.equal(metadata.entries, 249); assert.equal(metadata.networkAtRuntime, false);
  assert.deepEqual(metadata.sources.map(source => source.license), ['CC-BY-4.0', 'Public domain']);
  for (const source of metadata.sources) { assert.match(source.url, /^https:\/\//); assert.match(source.sha256, /^[a-f0-9]{64}$/); }
  assert.ok(metadata.unplaced.some(reason => reason.startsWith('BQ:')));
});
