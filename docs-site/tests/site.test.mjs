import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';

test('publishes searchable documentation and a useful missing-page response', () => {
  assert.ok(existsSync('dist/index.html'), 'The documentation home page is built');
  const index = JSON.parse(readFileSync('dist/search-index.json', 'utf8'));
  assert.ok(index.length >= 30, 'The full operational documentation is indexed');
  assert.ok(index.some(p => p.url === '/how-to/restore/' && p.text.includes('psql')));
  assert.match(readFileSync('dist/404.html', 'utf8'), /Page not found/);
});

test('article has semantic navigation, correct canonical and working section anchors', () => {
  assert.ok(existsSync('dist/how-to/deploy-server/index.html'), 'Deployment guide is built');
  const html = readFileSync('dist/how-to/deploy-server/index.html', 'utf8');
  assert.match(html, /https:\/\/docs.nimstead.systems\/how-to\/deploy-server\//);
  assert.match(html, /aria-current="page"/);
  assert.match(html, /id="start-the-services"/);
  assert.match(html, /href="#start-the-services"/);
  assert.ok(html.includes('href="/how-to/configure-https/"'));
});

test('company home leads with Assure and offers Pulse as a separate product', () => {
  const html = readFileSync('dist/index.html', 'utf8');
  assert.match(html, /<h1>Nimstead documentation<\/h1>/);
  assert.ok(html.indexOf('href="/assure/"') < html.indexOf('href="/pulse/"'));
  assert.ok(existsSync('dist/assure/index.html'));
  assert.ok(existsSync('dist/pulse/index.html'));
});

test('search identifies products and Pulse navigation does not mix Assure guides', () => {
  const index = JSON.parse(readFileSync('dist/search-index.json', 'utf8'));
  assert.ok(index.some(p => p.product === 'Assure' && p.url === '/how-to/restore/'));
  assert.ok(index.some(p => p.product === 'Pulse' && p.url === '/pulse/tutorials/first-triage/'));
  assert.ok(existsSync('dist/pulse/tutorials/first-triage/index.html'));
  const html = readFileSync('dist/pulse/tutorials/first-triage/index.html', 'utf8');
  assert.match(html, /href="\/pulse\/"/);
  assert.doesNotMatch(html, /href="\/how-to\/restore\/"/);
  assert.match(readFileSync('dist/search/index.html', 'utf8'), /id="search-product"/);
});

 test('operational articles expose source applicability and mobile section links', () => {
  const html = readFileSync('dist/how-to/deploy-server/index.html', 'utf8');
  assert.match(html, /Describes Assure source <a href="https:\/\/github.com\/Nimstead\/assure\/tree\/[a-f0-9]{40}">/);
  assert.match(html, /compare its version/);
  const contents = html.match(/<details class="local-contents">([\s\S]*?)<\/details>/)[1];
  assert.match(contents, /href="#start-the-services"/);
});


test('API lookup includes the downloadable schema and the complete endpoint catalog', () => {
  const schema = JSON.parse(readFileSync('dist/reference/openapi.json', 'utf8'));
  assert.equal(schema.openapi, '3.1.0');
  assert.ok(schema.paths['/api/assets/{asset_id}/sbom'].post);
  const html = readFileSync('dist/reference/api-endpoints/index.html', 'utf8');
  assert.match(html, /href="\/reference\/openapi.json"/);
  assert.match(html, /Asset upload\/agent key or admin session/);
});
