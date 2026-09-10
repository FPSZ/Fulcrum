/** Browser regression: run against `cd console && npm run dev`.
 * PLAYWRIGHT_MODULE may point to an existing Playwright installation.
 * No backend requests or real event actions are needed.
 */
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href
  : 'playwright')
const base = process.env.CONSOLE_URL ?? 'http://127.0.0.1:5173'
const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE,
})
const event = {
  id: 'a897b2b1512f4c56aa533bb19d44198c', sess: 'live-000293',
  risk: '工具调用阻断', level: 'critical', disp: 'block',
  srcType: '用户', trust: 'untrusted', tool: 'shell.exec',
  policy: 'block-dangerous-command', conf: 0.7, time: '12:29:57',
  verified: true, excerpt: '', intent: '', args: '', derived: '', reason: '',
}

try {
  const page = await browser.newPage()
  page.setDefaultTimeout(10000)
  page.on('pageerror', (error) => console.error(error))
  // Load the real component and Tailwind stylesheet through Vite, isolated from auth/API state.
  await page.route('**/__event-detail-layout-test', (route) => route.fulfill({
    contentType: 'text/html',
    body: `<!doctype html><html><body><div id="root"></div><script type="module">
      import RefreshRuntime from '/@react-refresh';
      RefreshRuntime.injectIntoGlobalHook(window);
      window.$RefreshReg$ = () => {};
      window.$RefreshSig$ = () => (type) => type;
      window.__vite_plugin_react_preamble_installed__ = true;
      const React = (await import('/node_modules/.vite/deps/react.js')).default;
      const { createRoot } = (await import('/node_modules/.vite/deps/react-dom_client.js')).default;
      const { EventDetail } = await import('/src/features/events/event-detail.tsx');
      const { TooltipProvider } = await import('/src/components/ui/index.ts');
      await import('/src/index.css');
      window.renderEvent = (event, compact) => {
        window.testRoot ??= createRoot(document.getElementById('root'));
        window.testRoot.render(React.createElement(TooltipProvider, null, React.createElement(EventDetail, {
          event, index: 0, total: 1, onBack: compact ? () => {} : undefined,
        })));
      };
    </script></body></html>`,
  }))
  await page.goto(`${base}/__event-detail-layout-test`)
  await page.waitForFunction(() => typeof window.renderEvent === 'function')
  for (const width of [1600, 1280, 1100, 390]) {
    await page.setViewportSize({ width, height: 900 })
    for (const longIds of [false, true]) {
      const sample = longIds
        ? { ...event, id: event.id.repeat(4), sess: event.sess.repeat(8) }
        : event
      await page.evaluate(({ sample, width }) => window.renderEvent(sample, width <= 1080), { sample, width })
      await page.getByRole('heading', { name: event.risk }).waitFor()
      await page.waitForFunction((id) => [...document.querySelectorAll('.font-data')].some((el) => el.textContent === id), sample.id)
      const result = await page.evaluate(({ id, sess }) => {
        const title = document.querySelector('h1')
        const header = title.closest('.px-\\[18px\\]')
        const value = (text) => [...header.querySelectorAll('.font-data')].find((el) => el.textContent === text)
        const session = value(sess)
        const eventId = value(id)
        const rect = (el) => el.getBoundingClientRect().toJSON()
        return {
          title: rect(title), session: rect(session), event: rect(eventId),
          header: rect(header), lineHeight: parseFloat(getComputedStyle(title).lineHeight),
          overflow: header.scrollWidth > header.clientWidth,
        }
      }, sample)
      const label = `${width}px / ${longIds ? 'long' : 'original'} IDs`
      assert.ok(result.title.height <= result.lineHeight + 1, `${label}: title must remain one line`)
      assert.ok(result.session.top >= result.title.bottom, `${label}: session must be below title`)
      assert.ok(result.event.top >= result.session.bottom, `${label}: event must be below session`)
      assert.ok(!result.overflow, `${label}: header must not overflow`)
      assert.ok(result.event.right <= result.header.right, `${label}: full ID must fit panel`)
      console.log(`PASS ${label}`)
      if (width === 1280 && !longIds && process.env.LAYOUT_SCREENSHOT) {
        await page.locator('aside').screenshot({ path: process.env.LAYOUT_SCREENSHOT, animations: 'disabled' })
      }
    }
  }
} finally {
  await browser.close()
}
