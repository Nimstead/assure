import {readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, existsSync} from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import MarkdownIt from 'markdown-it';

const root = path.resolve('..');
const out = path.resolve('dist');
const origin = 'https://docs.nimstead.systems';
const repo = 'https://github.com/Nimstead/assure';
const sourceRef = process.env.DOCS_SOURCE_REF || execFileSync('git',['branch','--show-current'],{encoding:'utf8'}).trim() || 'main';
const pages = JSON.parse(readFileSync('pages.json','utf8'));
const products = JSON.parse(readFileSync('products.json','utf8'));
const categoryNames = ['tutorials','how-to','reference','explanation'];
const categoryUrl = (product, index) => (product === 'assure' ? '/' : '/'+product+'/') + categoryNames[index]+'/';
const productFor = url => pages.find(p=>'/'+p.slug+'/'===url)?.product || (url.startsWith('/pulse/') ? 'pulse' : url.startsWith('/assure/') || categoryNames.some(c=>url.startsWith('/'+c+'/')) ? 'assure' : '');
const groups = ['Tutorials','How-to guides','Reference','Explanation'];
const descriptions = ['Learn with a safe, worked example.','Follow steps to complete a specific task.','Find commands, settings, formats, and limits.','Understand the system and its tradeoffs.'];
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sourceMap = new Map(pages.map(p => [path.resolve(root,p.source), '/'+p.slug+'/']));
sourceMap.set(path.resolve(root,'docs/README.md'), '/assure/');
const md = new MarkdownIt({html:false, linkify:false});
const slug = text => text.toLowerCase().replace(/[^\p{L}\p{N}_\- ]/gu,'').replace(/ /g,'-');
md.renderer.rules.heading_open = (tokens,i,options,env,self) => {
  const text = tokens[i+1].content.replace(/[`*_]/g,'');
  let id = slug(text); const count = env.ids.get(id) || 0; env.ids.set(id,count+1);
  if (count) id += '-'+count;
  tokens[i].attrSet('id',id);
  if (tokens[i].tag === 'h2') env.headings.push({id,text});
  return self.renderToken(tokens,i,options);
};
const originalLink = md.renderer.rules.link_open || ((t,i,o,e,s) => s.renderToken(t,i,o));
md.renderer.rules.link_open = (tokens,i,options,env,self) => {
  const href = tokens[i].attrGet('href');
  if (href && !/^(?:[a-z][a-z\d+.-]*:|\/\/|#)/i.test(href)) {
    const [file,fragment] = href.split('#');
    const target = path.resolve(root,path.dirname(env.source),decodeURIComponent(file));
    const local = sourceMap.get(target);
    let resolved;
    if (local) resolved = local;
    else if (target.includes(path.join('docs','examples')+path.sep)) resolved = '/examples/'+path.basename(target);
    else resolved = repo+'/blob/'+sourceRef+'/'+path.relative(root,target).split(path.sep).map(encodeURIComponent).join('/');
    tokens[i].attrSet('href',resolved+(fragment?'#'+fragment:''));
  }
  return originalLink(tokens,i,options,env,self);
};
md.renderer.rules.table_open = () => '<div class="table-scroll" tabindex="0" role="region" aria-label="Reference table"><table>\n';
md.renderer.rules.table_close = () => '</table></div>\n';
function nav(current, mobile=false) {
  const productId = productFor(current);
  const product = products.find(p=>p.id===productId);
  const articles = pages.filter(p=>p.product===productId);
  return `<nav aria-label="${mobile?'Mobile documentation':'Documentation'}"><a class="rail-home" href="/" ${current==='/'?'aria-current="page"':''}>All documentation</a><div class="product-links">${products.map(p=>`<a href="/${p.id}/" ${current==='/'+p.id+'/'?'aria-current="page"':''} ${p.id===productId?'class="selected-product"':''}>${p.name}</a>`).join('')}</div>${product?`<p class="nav-product">${product.name} documentation</p>${groups.map(group=>`<details ${pages.find(p=>'/'+p.slug+'/'===current)?.group===group?'open':''}><summary>${group}</summary><ul>${articles.filter(p=>p.group===group).map(p=>`<li><a href="/${p.slug}/" ${current==='/'+p.slug+'/'?'aria-current="page"':''}>${esc(p.title)}</a></li>`).join('')}</ul></details>`).join('')}`:''}<div class="rail-bottom"><a href="/search/">Search all products</a>${product?`<a href="${product.repo}">${product.name} source</a>`:''}<a href="${repo}/issues">Report a docs issue</a><a href="https://nimstead.systems/security/">Security</a></div></nav>`;
}
function layout({title,url,body,description='',group='',headings=[],source=''}) {
  const product = products.find(p=>p.id===productFor(url));
  const outline = headings.length?`<aside class="outline" aria-label="On this page"><p>On this page</p><ul>${headings.map(h=>`<li><a href="#${esc(h.id)}">${esc(h.text)}</a></li>`).join('')}</ul></aside>`:'';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)} · Nimstead Docs</title><meta name="description" content="${esc(description)}"><link rel="canonical" href="${origin}${url}"><meta property="og:title" content="${esc(title)} · Nimstead Docs"><meta property="og:description" content="${esc(description)}"><meta property="og:type" content="website"><meta property="og:url" content="${origin}${url}"><link rel="icon" href="/favicon.svg"><link rel="preload" href="/assets/archivo.woff2" as="font" type="font/woff2" crossorigin><script src="/theme.js"></script><link rel="stylesheet" href="/style.css"><script src="/site.js" defer></script></head><body><a class="skip" href="#main">Skip to content</a><header class="header"><a class="brand" href="https://nimstead.systems" aria-label="Nimstead home">Nimstead<span class="seal" aria-hidden="true"></span></a><a class="header-label" href="/">Documentation</a><div class="header-actions"><a class="search-link" href="/search/">Search docs <kbd aria-hidden="true">⌘ K</kbd></a><a class="external" href="${product?.repo || 'https://github.com/Nimstead'}">GitHub</a><label class="sr-only" for="theme">Colour theme</label><select id="theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></div></header><details class="mobile-nav"><summary>Browse documentation</summary>${nav(url,true)}</details><div class="shell"><aside class="rail">${nav(url)}</aside><main id="main" class="content" tabindex="-1"><div class="crumb"><a href="/">Documentation</a>${product?`<span aria-hidden="true">/</span><a href="/${product.id}/">${product.name}</a>`:''}${group?`<span aria-hidden="true">/</span><span>${esc(group)}</span>`:''}</div>${source?`<div class="article-layout"><article>${body}<div class="article-footer"><a href="${repo}/blob/${sourceRef}/${source}">View Markdown source</a><a href="${repo}/edit/${sourceRef}/${source}">Edit this page</a></div></article>${outline}</div>`:body}<footer class="site-footer"><span>Nimstead · Software that shows its working.</span><span><a href="https://nimstead.systems/privacy/">Privacy</a> · <a href="${repo}">Source on GitHub</a></span></footer></main></div><div id="copy-status" class="sr-only" role="status" aria-live="polite"></div></body></html>`;
}
function save(url,html) { const file=path.join(out,url==='404'? '404.html':url,'index.html'); const target=url==='404'?path.join(out,'404.html'):file; mkdirSync(path.dirname(target),{recursive:true});writeFileSync(target,html); }
rmSync(out,{recursive:true,force:true});mkdirSync(out,{recursive:true});cpSync('public',out,{recursive:true});
cpSync(path.join(root,'docs/examples'),path.join(out,'examples'),{recursive:true});
const index=[];
for (const p of pages) {
  const markdown=readFileSync(path.join(root,p.source),'utf8');
  const env={source:p.source,headings:[],ids:new Map()};
  const html=md.render(markdown.replace(/^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]$/gm, (_, label) => '> **'+label[0]+label.slice(1).toLowerCase()+'.**'),env);
  const text=html.replace(/<[^>]*>/g,' ').replace(/&[^;]+;/g,' ').replace(/\s+/g,' ').trim();
  const siblings=pages.filter(page=>page.product===p.product);
  const position=siblings.indexOf(p);
  const next=siblings[position+1],prev=siblings[position-1];
  const adjacent=`<nav class="page-nav" aria-label="Adjacent pages">${prev?`<a href="/${prev.slug}/"><span>Previous</span>${esc(prev.title)}</a>`:'<span></span>'}${next?`<a href="/${next.slug}/"><span>Next</span>${esc(next.title)}</a>`:''}</nav>`;
  save(p.slug,layout({title:p.title,url:'/'+p.slug+'/',description:text.slice(p.title.length, p.title.length+160).trim(),group:p.group,headings:env.headings,source:p.source,body:html+adjacent}));
  index.push({title:p.title,url:'/'+p.slug+'/',group:p.group,product:products.find(product=>product.id===p.product).name,text});
}
const assureHome=`<div class="home"><h1>Assure documentation</h1><p class="home-lead">Install it. Understand the findings. Make changes with care. Keep evidence you can check.</p><div class="start"><div><h2>New to Assure?</h2><p>Read a small software inventory and see how Assure identifies its packages. No server required.</p><a href="/tutorials/first-sbom/">Read your first SBOM →</a></div><div><h2>Ready to run it?</h2><p>Deploy the server on your infrastructure, then connect your first machine.</p><a href="/how-to/deploy-server/">Deploy with Docker Compose →</a></div></div><div class="directory">${groups.map((g,i)=>`<section><h2>${g}</h2><p>${descriptions[i]}</p><ul>${pages.filter(p=>p.group===g && p.product==='assure').slice(0,5).map(p=>`<li><a href="/${p.slug}/">${esc(p.title)}</a></li>`).join('')}</ul><a class="browse-all" href="/${['tutorials','how-to','reference','explanation'][i]}/">Browse all ${g.toLowerCase()} →</a></section>`).join('')}</div><p class="note">These pages describe the current Assure source. For a deployed release, check its version and <a href="${repo}/releases">release notes</a>. <a href="/explanation/coverage-limits/">Coverage limits</a> explain where the evidence stops.</p></div>`;
save('assure',layout({title:'Assure documentation',url:'/assure/',description:'Tutorials, practical guides, reference, and explanations for operating Nimstead Assure.',body:assureHome}));
const directory = product => `<div class="directory">${groups.map((g,i)=>`<section><h2>${g}</h2><p>${descriptions[i]}</p><ul>${pages.filter(p=>p.product===product.id && p.group===g).map(p=>`<li><a href="/${p.slug}/">${esc(p.title)}</a></li>`).join('')}</ul><a class="browse-all" href="${categoryUrl(product.id,i)}">Browse ${g.toLowerCase()} →</a></section>`).join('')}</div>`;
const pulse = products.find(p=>p.id==='pulse');
save('pulse',layout({title:'Pulse documentation',url:'/pulse/',description:pulse.summary,body:`<div class="home"><h1>Pulse documentation</h1><p class="home-lead">Read the public signals. Review your CVEs privately. Keep the limits in view.</p><div class="start"><div><h2>Start with the example</h2><p>Use a fixed list of public CVEs to understand coverage, priority, and source dates.</p><a href="/pulse/tutorials/first-triage/">Read your first triage →</a></div><div><h2>Bring your own list</h2><p>Analyse a CVE list in your browser, save a snapshot, and prepare a handover.</p><a href="/pulse/how-to/analyse-list/">Analyse your CVE list →</a></div></div>${directory(pulse)}<p class="note">Pulse uses public feeds. It does not establish whether a particular host is affected or remediated. <a href="/pulse/explanation/pulse-and-assure/">See how Pulse and Assure fit together.</a></p></div>`}));
const companyHome = `<div class="home company-home"><h1>Nimstead documentation</h1><p class="home-lead">Practical guides, precise references, and explanations for the software you use.</p><div class="product-directory">${products.map(p=>`<section class="product-row"><div><h2><a href="/${p.id}/">${p.name}</a></h2><p>${p.summary}</p><a class="product-open" href="/${p.id}/">Open ${p.name} documentation →</a></div><ul>${groups.map((g,i)=>`<li><a href="${categoryUrl(p.id,i)}">${g}</a></li>`).join('')}</ul></section>`).join('')}</div><p class="note">New here? Start with a tutorial. Use a how-to guide for a task, reference for a specific detail, and explanation for the reasoning behind it.</p></div>`;
save('',layout({title:'Nimstead documentation',url:'/',description:'Documentation for Nimstead Assure and Pulse: tutorials, how-to guides, reference, and explanations.',body:companyHome}));
save('search',layout({title:'Search documentation',url:'/search/',body:'<article><h1>Search documentation</h1><form id="search-form" class="search-form" action="/search/" role="search"><label class="sr-only" for="search-input">Search documentation</label><input id="search-input" name="q" type="search" placeholder="Try backup, SSO, or enrolment…" autocomplete="off"><button type="submit">Search</button></form><div class="search-filters"><label for="search-product">Product</label><select id="search-product"><option value="">All products</option><option value="Assure">Assure</option><option value="Pulse">Pulse</option></select></div><p class="search-status" id="search-status" role="status" aria-live="polite">Search by task, command, setting, or error message.</p><noscript><p>Search requires JavaScript. Use the documentation navigation to browse every page.</p></noscript><ul class="results" id="search-results"></ul></article>'}));
save('404',layout({title:'Page not found',url:'/404/',body:'<article><h1>Page not found</h1><p>This address does not match a documentation page. It may have moved.</p><p><a href="/search/">Search the documentation</a> or <a href="/">return to the contents</a>.</p></article>'}));
writeFileSync(path.join(out,'search-index.json'),JSON.stringify(index));
const categoryPaths=[];
for (const product of products) {
  for (const [i,g] of groups.entries()) {
    const url=categoryUrl(product.id,i);
    categoryPaths.push(url);
    save(url, layout({title:`${product.name} ${g.toLowerCase()}`,url,body:`<article><h1>${g}</h1><p>${descriptions[i]}</p><ul class="category-list">${pages.filter(p=>p.group===g && p.product===product.id).map(p=>`<li><a href="/${p.slug}/">${esc(p.title)}</a></li>`).join('')}</ul></article>`}));
  }
}
const urls=['/','/search/',...products.map(p=>'/'+p.id+'/'),...categoryPaths,...pages.map(p=>'/'+p.slug+'/')];
writeFileSync(path.join(out,'sitemap.xml'),`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(url=>`<url><loc>${origin}${url}</loc></url>`).join('')}</urlset>`);
writeFileSync(path.join(out,'robots.txt'),`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
writeFileSync(path.join(out,'_headers'),`/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'\n`);
// Fail the build if a generated local destination or heading does not exist.
for (const url of urls) {
  const html=readFileSync(path.join(out,url,'index.html'),'utf8');
  for (const match of html.matchAll(/(?:href|src)="([^" ]+)"/g)) {
    const target=match[1]; if(!target.startsWith('/') && !target.startsWith('#')) continue;
    const [pathname,fragment]=target.split('#');
    let file=path.join(out,pathname||url); if((pathname||url).endsWith('/')) file=path.join(file,'index.html');
    if(!existsSync(file)) throw Error(`Broken local link on ${url}: ${target}`);
    if(fragment && file.endsWith('.html') && !readFileSync(file,'utf8').includes(`id="${fragment}"`)) throw Error(`Broken heading on ${url}: ${target}`);
  }
}
console.log(`Built ${pages.length} articles, home, search and 404. All local links and heading targets pass.`);
