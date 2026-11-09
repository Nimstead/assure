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
