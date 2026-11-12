// Smoke-test every tool page with headless Chromium: catch render errors,
// console errors and React warnings. Not part of the app build.
import { chromium } from 'playwright-core';
import { execSync } from 'node:child_process';

const BASE = process.env.BASE ?? 'http://127.0.0.1:5178';
const exe = execSync(
  'ls -d "$HOME"/Library/Caches/ms-playwright/chromium-*/chrome-mac-x64/*.app/Contents/MacOS/* | head -1',
  { shell: '/bin/bash' },
)
  .toString()
  .trim();

const mod = await (await fetch(BASE + '/src/tools/registry.ts')).text();
const paths = [...mod.matchAll(/path:\s*"([^"]+)"/g)].map((x) => x[1]);
if (paths.length < 50) throw new Error(`only ${paths.length} tool paths parsed from the registry`);

const browser = await chromium.launch({ executablePath: exe, args: ['--disable-gpu'] });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' });
const failures = [];

for (const p of ['', 'about', ...paths]) {
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (msg) => {
    const t = msg.text();
    if (msg.type() === 'error' || /Warning:/.test(t)) errors.push(t.slice(0, 300));
  });
  page.on('pageerror', (e) => errors.push('pageerror: ' + String(e).slice(0, 300)));
  const url = `${BASE}/${p}`;
  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForTimeout(150);
    const h1 = ((await page.locator('h1').first().textContent().catch(() => '')) ?? '').trim();
    const bodyLen = (await page.locator('body').innerText()).length;
    if (bodyLen < 60) errors.push(`suspiciously empty body (${bodyLen} chars)`);
    if (!p && !/offensive security toolkit/i.test(h1)) errors.push('home heading missing');
    if (p && p !== 'about' && !h1) errors.push('tool h1 missing');
    // Interaction coverage: type into the first text field, then every button once.
    const fields = page.locator('main input[type="text"], main textarea, main input:not([type])');
    if (await fields.count()) {
      await fields.first().fill('example.com/admin?id=1').catch(() => {});
      await page.waitForTimeout(80);
    }
    const buttons = page.locator('main button');
    const n = Math.min(await buttons.count(), 12);
    for (let i = 0; i < n; i++) {
      await buttons.nth(i).click({ timeout: 1500, force: false }).catch(() => {});
      await page.waitForTimeout(40);
    }
  } catch (e) {
    errors.push('nav: ' + String(e).slice(0, 200));
  }
  if (errors.length) failures.push({ path: p || '/', errors: [...new Set(errors)].slice(0, 5) });
  await page.close();
}

await browser.close();
if (!failures.length) {
  console.log(`OK — ${paths.length + 2} routes clean (typed + clicked through)`);
} else {
  for (const f of failures) console.log(`\n${f.path}\n  ` + f.errors.join('\n  '));
  console.log(`\n${failures.length} route(s) with issues`);
  process.exitCode = 1;
}
