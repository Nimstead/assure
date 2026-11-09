const theme = document.querySelector('#theme');
if (theme) {
  theme.value = document.documentElement.dataset.theme || 'system';
  theme.addEventListener('change', () => {
    if (theme.value === 'system') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme.value;
    try { localStorage.setItem('nimstead-docs-theme', theme.value); } catch {}
  });
}
for (const pre of document.querySelectorAll('pre')) {
  const code = pre.querySelector('code');
  if (!code || !navigator.clipboard) continue;
  const button = document.createElement('button');
  button.className = 'copy'; button.textContent = 'Copy';
  button.setAttribute('aria-label', 'Copy code');
  button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(code.textContent); button.textContent = 'Copied'; }
    catch { button.textContent = 'Select and copy'; }
    document.querySelector('#copy-status').textContent = button.textContent === 'Copied' ? 'Code copied to clipboard.' : 'Clipboard access failed. Select the code and copy it manually.';
    setTimeout(() => { button.textContent = 'Copy'; }, 2200);
  });
  pre.append(button);
}
const input = document.querySelector('#search-input');
if (input) {
  const results = document.querySelector('#search-results');
  const status = document.querySelector('#search-status');
  const form = document.querySelector('#search-form');
  let index;
  input.value = new URLSearchParams(location.search).get('q') || '';
  const render = () => {
    if (!index) return;
    const query = input.value.trim().toLocaleLowerCase();
    results.replaceChildren();
    if (!query) { status.textContent = 'Search by task, command, setting, or error message.'; return; }
    const terms = query.split(/\s+/);
    const matches = index.map(p => ({...p, score: terms.reduce((s,t) => s + (p.title.toLowerCase().includes(t) ? 12 : 0) + (p.text.toLowerCase().includes(t) ? 1 : 0), 0)}))
      .filter(p => terms.every(t => (p.title + ' ' + p.text).toLowerCase().includes(t)))
      .sort((a,b) => b.score - a.score).slice(0,30);
    status.textContent = matches.length ? `${matches.length} ${matches.length === 1 ? 'page' : 'pages'} found.` : 'No pages found. Try a shorter term, such as “backup”, “SSO”, or “token”.';
    for (const page of matches) {
      const li = document.createElement('li');
      const a = document.createElement('a'); a.href = page.url; a.textContent = page.title;
      const group = document.createElement('span'); group.textContent = page.group;
      const p = document.createElement('p');
      const at = page.text.toLowerCase().indexOf(terms[0]);
      const start = Math.max(0, at - 65);
      p.textContent = (start ? '…' : '') + page.text.slice(start, start + 210) + '…';
      li.append(group, a, p); results.append(li);
    }
  };
  input.addEventListener('input', render);
  form.addEventListener('submit', event => { event.preventDefault(); history.replaceState(null,'',`/search/?q=${encodeURIComponent(input.value)}`); render(); });
  status.textContent = 'Loading the documentation index…';
  fetch('/search-index.json').then(r => { if (!r.ok) throw Error(); return r.json(); }).then(data => { index = data; render(); })
    .catch(() => { status.textContent = 'The search index could not load. Reload this page, or use the contents navigation.'; });
}
document.addEventListener('keydown', event => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'k') { event.preventDefault(); location.href = '/search/'; }
});
