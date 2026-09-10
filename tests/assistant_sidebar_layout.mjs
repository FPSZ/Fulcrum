/** Run against `cd console && npm run dev`, then `node tests/assistant_sidebar_layout.mjs`.
 * Optional: CONSOLE_URL, PLAYWRIGHT_MODULE (module file), PLAYWRIGHT_CHROMIUM_EXECUTABLE,
 * LAYOUT_SCREENSHOT (output PNG). Uses isolated browser state; no backend writes.
 */
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright')
const browser = await chromium.launch({
  headless: true, executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE,
})
try {
  const page = await browser.newPage({ viewport: { width: 1000, height: 600 } })
  page.setDefaultTimeout(5000)
  await page.route('**/__assistant-sidebar-test', (route) => route.fulfill({
    contentType: 'text/html',
    body: `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="root" style="height:600px;display:flex"></div>
    <script type="module">
      import RefreshRuntime from '/@react-refresh';
      RefreshRuntime.injectIntoGlobalHook(window);
      window.$RefreshReg$ = () => {};
      window.$RefreshSig$ = () => (type) => type;
      window.__vite_plugin_react_preamble_installed__ = true;
      const React = (await import('/node_modules/.vite/deps/react.js')).default;
      const { createRoot } = (await import('/node_modules/.vite/deps/react-dom_client.js')).default;
      const { ConversationSidebar } = await import('/src/features/assistant/conversation-sidebar.tsx');
      const { setLocale } = await import('/src/lib/i18n/index.ts');
      await import('/src/index.css');
      const root = createRoot(document.getElementById('root'));
      window.renderSidebar = (count, collapsed, locale) => {
        setLocale(locale);
        root.render(React.createElement(ConversationSidebar, {
          history: Array.from({ length: count }, (_, i) => ({ id: String(i), title: '会话 ' + i, messages: [], updatedAt: 0 })),
          activeId: '0', busy: false, collapsed,
          onToggle() {}, onNew() {}, onSelect() {}, onDelete() {},
        }));
      };
    </script></body></html>`,
  }))
  await page.goto(`${process.env.CONSOLE_URL ?? 'http://127.0.0.1:5173'}/__assistant-sidebar-test`)
  await page.waitForFunction(() => typeof window.renderSidebar === 'function')
  for (const locale of ['zh', 'en']) {
    const text = locale === 'zh' ? 'AI 可能出错,请核对结果' : 'AI can make mistakes — please verify the results'
    for (const count of [0, 3, 80]) {
      await page.evaluate(({ count, locale }) => window.renderSidebar(count, false, locale), { count, locale })
      const note = page.getByText(text, { exact: true })
      await note.waitFor()
      assert.equal(await note.count(), 1)
      const bounds = await note.evaluate((el) => {
        const aside = el.closest('aside')
        const list = aside.querySelector('.overflow-y-auto')
        list.scrollTop = list.scrollHeight
        const rect = (node) => node.getBoundingClientRect().toJSON()
        return { note: rect(el), aside: rect(aside), list: rect(list) }
      })
      assert.ok(bounds.note.top >= bounds.list.bottom, 'notice must be outside the scrolling history')
      assert.ok(bounds.note.bottom <= bounds.aside.bottom, 'notice must stay inside sidebar')
      assert.ok(bounds.aside.bottom - bounds.note.bottom <= 24, 'notice must stay at sidebar bottom')
      console.log(`PASS ${locale}, ${count} conversations`)
      if (locale === 'zh' && count === 3 && process.env.LAYOUT_SCREENSHOT) {
        await page.locator('aside').screenshot({ path: process.env.LAYOUT_SCREENSHOT, animations: 'disabled' })
      }
    }
    await page.evaluate((locale) => window.renderSidebar(3, true, locale), locale)
    await page.getByText(text, { exact: true }).waitFor({ state: 'hidden' })
    console.log(`PASS ${locale}, collapsed sidebar`)
  }
  const source = await readFile(new URL('../console/src/features/assistant/assistant-page.tsx', import.meta.url), 'utf8')
  assert.ok(!source.includes("t('assistant.disclaimer')"), 'chat composer must not reserve a disclaimer row')
  console.log('PASS no disclaimer row in chat area')
} finally {
  await browser.close()
}
