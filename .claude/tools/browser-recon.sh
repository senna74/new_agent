#!/bin/bash
# browser-recon.sh — Authenticated browser recon using Playwright
# Usage: browser-recon.sh <cookies> <project_url> <output_dir>

COOKIES=$1
PROJECT_URL=$2
OUTDIR=$3

mkdir -p "$OUTDIR/js" "$OUTDIR/endpoints"

echo "[browser-recon] Starting on $PROJECT_URL"

python3 << PYEOF
import subprocess, os

cookies_str = """$COOKIES"""
project_url = "$PROJECT_URL"
outdir = "$OUTDIR"

script = '''
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();

  const cookieParts = `''' + cookies_str + '''`.split(';');
  const cookies = cookieParts.map(p => {
    const [name, ...rest] = p.trim().split('=');
    return { name: name.trim(), value: rest.join('=').trim(), domain: 'mixpanel.com', path: '/' };
  }).filter(c => c.name && c.value);
  await context.addCookies(cookies);

  const jsUrls = new Set();
  const apiCalls = new Set();

  context.on('request', req => {
    const url = req.url();
    if (url.match(/\\.js(\\?|$)/) && !url.match(/google|facebook|twitter|optimizely/))
      jsUrls.add(url);
    if (url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/')) {
      try { apiCalls.add(new URL(url).pathname); } catch(e) {}
    }
  });

  const page = await context.newPage();
  try {
    await page.goto("''' + project_url + '''", { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(5000);
    // Navigate to key sections to trigger more API calls
    const links = await page.$$eval('a[href]', els => els.map(e => e.href).filter(h => h.includes('mixpanel.com')));
    for (const link of links.slice(0, 10)) {
      try {
        await page.goto(link, { waitUntil: 'networkidle', timeout: 15000 });
        await page.waitForTimeout(2000);
      } catch(e) {}
    }
  } catch(e) { console.error('Nav error:', e.message); }

  const fs = require('fs');
  fs.writeFileSync(outdir + '/js/browser-js-urls.txt', [...jsUrls].join('\\n'));
  fs.writeFileSync(outdir + '/endpoints/browser-api-calls.txt', [...apiCalls].join('\\n'));
  console.log('JS URLs:', jsUrls.size);
  console.log('API calls:', apiCalls.size);
  await browser.close();
})();
'''.replace('outdir', f'"{outdir}"')

script_path = f"{outdir}/playwright-recon.js"
with open(script_path, 'w') as f:
    f.write(script)

result = subprocess.run(['node', script_path], capture_output=True, text=True, timeout=120)
print(result.stdout)
if result.stderr:
    print('STDERR:', result.stderr[:300])
PYEOF

echo "[browser-recon] Done"
echo "[browser-recon] JS URLs: $(wc -l < $OUTDIR/js/browser-js-urls.txt 2>/dev/null || echo 0)"
echo "[browser-recon] API calls: $(wc -l < $OUTDIR/endpoints/browser-api-calls.txt 2>/dev/null || echo 0)"
