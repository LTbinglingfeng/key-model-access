const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

// Execute production functions, stopping before event wiring / UI startup.
const source = readFileSync(join(__dirname, 'settings.js'), 'utf8');
const marker = '  $("#retrySessionButton").addEventListener';
assert.equal(source.split(marker).length, 2);
function load(respond = () => { throw new Error('Unexpected fetch'); }, globals = {}) {
  const context = vm.createContext({
    document: { querySelector: () => null },
    window: { setTimeout, clearTimeout },
    ...globals,
    AbortController, TextEncoder, TextDecoder, atob,
    fetch: async (path, options) => {
      const payload = await respond(path, options);
      return { ok: true, json: async () => payload };
    }
  });
  vm.runInContext(source.slice(0, source.indexOf(marker)) +
    'globalThis.helpers = { pluginsDirFromList, initializeDefaultPersistence, fetchCurrentKeys, api, normalizePolicyDocument, readCPAMCManagementKey, readStoredValue, connectManually, connectFromCPAMC, state, MESSAGES, t, getLocale: () => locale }; })();', context);
  return context.helpers;
}

// Independent fixture encoder matching CPAMC src/utils/encryption.ts.
function storedFixture(value, version = 2, host = 'localhost:8317', ua = 'old-browser') {
  const bytes = Buffer.from(JSON.stringify(value));
  const key = Buffer.from(`cli-proxy-api-webui::secure-storage|${host}${version === 1 ? `|${ua}` : ''}`);
  return `enc::v${version}::` + Buffer.from(bytes.map((byte, index) => byte ^ key[index % key.length])).toString('base64');
}

function sessionHelpers(auth, loggedIn = 'true', extra = {}, ua = 'new-browser') {
  const values = { 'cli-proxy-auth': auth, isLoggedIn: loggedIn, ...extra };
  return load(undefined, {
    window: { location: { host: 'localhost:8317' } },
    navigator: { userAgent: ua, languages: ['en'] },
    // Deliberately read-only: any attempted write fails the test.
    localStorage: { getItem: name => values[name] ?? null }
  });
}

test('manual fallback: missing session shows form; submit clears key and verifies with CPA', async () => {
  const elements = new Map();
  const element = selector => {
    if (!elements.has(selector)) elements.set(selector, {
      hidden: false, value: '', classList: { toggle() {} }, focus() { this.focused = true; }
    });
    return elements.get(selector);
  };
  let calls = 0;
  const helpers = load((_path, options) => {
    calls++;
    assert.equal(options.headers.Authorization, 'Bearer manual-test-key');
    assert.equal(element('#managementKey').value, '');
    const error = new Error('Unauthorized');
    error.status = 401;
    throw error;
  }, {
    document: { querySelector: element },
    localStorage: { getItem: () => null }
  });
  await helpers.connectFromCPAMC();
  assert.equal(element('#authForm').hidden, false);
  const event = { preventDefault() {} };
  element('#managementKey').value = '  ';
  await helpers.connectManually(event);
  assert.equal(calls, 0);
  assert.equal(element('#managementKey').focused, true);
  element('#managementKey').value = ' manual-test-key ';
  await helpers.connectManually(event);
  assert.equal(calls, 1);
  assert.equal(helpers.state.sessionSource, 'manual');
  assert.equal(helpers.state.token, '');
  assert.equal(helpers.state.sessionBusy, false);
  assert.equal(element('#authForm').hidden, false);
  assert.equal(helpers.state.sessionView.messageKey, 'session.expired');
});

test('CPAMC v2 session: reads Unicode keys independently of user agent', () => {
  const raw = storedFixture({ state: { managementKey: '  test-密钥-&<>  ', rememberPassword: true }, version: 0 });
  for (const ua of ['old-browser', 'new-browser']) {
    assert.equal(sessionHelpers(raw, 'true', {}, ua).readCPAMCManagementKey(), 'test-密钥-&<>');
  }
});

test('CPAMC auth: rejects retired, logged-out, malformed and missing credentials', () => {
  const data = { state: { managementKey: 'retired-test-key' } };
  const legacy = { managementKey: storedFixture('legacy-test-key', 1) };
  for (const raw of [null, JSON.stringify(data), storedFixture(data, 1), 'enc::v3::abc',
    'enc::v2::!!!', 'enc::v2::', storedFixture(null), storedFixture({}),
    storedFixture({ state: { managementKey: 123 } }), storedFixture({ state: { managementKey: '  ' } }),
    storedFixture({ state: { rememberPassword: false } })]) {
    assert.equal(sessionHelpers(raw, 'true', legacy).readCPAMCManagementKey(), '');
  }
  for (const flag of [null, 'false', '']) {
    assert.equal(sessionHelpers(storedFixture(data), flag).readCPAMCManagementKey(), '');
  }
  const blocked = load(undefined, { localStorage: { getItem() { throw new Error('Blocked'); } } });
  assert.equal(blocked.readCPAMCManagementKey(), '');
});

test('non-auth storage retains v1 and plaintext compatibility alongside v2', () => {
  for (const raw of [storedFixture('zh-CN', 1), storedFixture('zh-CN'), JSON.stringify('zh-CN')]) {
    assert.equal(sessionHelpers(null, 'true', { 'cli-proxy-language': raw }, 'old-browser').readStoredValue('cli-proxy-language'), 'zh-CN');
  }
});

test('plugins list: exactly five Go entities, one pass, no HTML parser', () => {
  const { pluginsDirFromList: decode } = load();
  assert.equal(decode({ plugins_dir: '/a&amp;&lt;&gt;&#34;&#39;' }), '/a&<>"\'');
  assert.equal(decode({ plugins_dir: '/&amp;lt;/&amp;#34;/&amp;amp;' }), '/&lt;/&#34;/&amp;');
  assert.equal(decode({ plugins_dir: '/&quot;/&apos;/&#x27;/&#60;/&AMP;' }), '/&quot;/&apos;/&#x27;/&#60;/&AMP;');
  assert.equal(decode({ plugins_dir: '/旧目录/plain&<>' }), '/旧目录/plain&<>');
  for (const value of [null, {}, { plugins_dir: 3 }]) assert.equal(decode(value), '');
  // Document the unavoidable old-host ambiguity rather than guessing.
  assert.equal(decode({ plugins_dir: '/legacy/&lt;' }), '/legacy/<');
});

test('initialization decodes only list directory; plugin path survives POST/PATCH/status', async () => {
  const policyFile = '/data/&lt;/&#34;/策略.json';
  const calls = [];
  const helpers = load((path, options) => {
    calls.push([path, options]);
    if (path === '/v0/management/plugins') return { plugins_dir: '/data/&amp;lt;/&#34;' };
    if (path.endsWith('/initialize-storage')) return { policy_file: policyFile };
    if (path.endsWith('/config')) return {};
    if (path.endsWith('/status')) return { persistent_updates: true, policy_file: policyFile };
    throw new Error(path);
  });
  assert.equal((await helpers.initializeDefaultPersistence()).policy_file, policyFile);
  assert.equal(calls.length, 4);
  assert.equal(calls[1][1].method, 'POST');
  assert.deepEqual(JSON.parse(calls[1][1].body), { plugins_dir: '/data/&lt;/"' });
  assert.equal(calls[2][1].method, 'PATCH');
  assert.deepEqual(JSON.parse(calls[2][1].body), { policy_file: policyFile });
});

test('null and empty API key arrays accepted, missing/invalid types rejected', async () => {
  for (const raw of [null, []]) {
    const helpers = load(() => ({ 'api-keys': raw }));
    assert.equal((await helpers.fetchCurrentKeys()).length, 0);
    const result = await helpers.fetchCurrentKeys({ includeCatalog: true });
    assert.equal(result.keys.length, 0);
    assert.equal(result.catalog.models.length, 0);
  }
  for (const payload of [null, {}, { 'api-keys': undefined }, ...['', 'key', 0, false, {}].map(value => ({ 'api-keys': value }))]) {
    await assert.rejects(load(() => payload).fetchCurrentKeys(), /API Key/);
  }
});

test('API keys are hashed and sent to model catalog without entity decoding', async () => {
  const key = 'sk-&amp;&lt;&#34;&#39;';
  const helpers = load((path, options) => {
    if (path === '/v0/management/api-keys') return { 'api-keys': [key] };
    assert.equal(path, '/v1/models');
    assert.equal(options.headers.Authorization, `Bearer ${key}`);
    return { data: [{ id: 'model-&lt;' }] };
  });
  const result = await helpers.fetchCurrentKeys({ includeCatalog: true });
  assert.equal(result.keys[0].scope, createHash('sha256').update(`cli-proxy-api:caller-scope:v1\0${key}`).digest('hex'));
  assert.equal(result.catalog.models[0].id, 'model-&lt;');
});

test('generic API and policy normalization preserve plugin entity literals', async () => {
  const policy = { version: 2, policies: [{ caller_scope: 'a'.repeat(64), allow_models: ['m-&lt;', 'm-&#34;'], deny_models: ['m-&amp;'] }] };
  const helpers = load(() => ({ policy, error: '&lt;error&gt;' }));
  const response = await helpers.api('/v0/management/plugins/key-model-access/policies');
  assert.equal(response.error, '&lt;error&gt;');
  assert.equal(JSON.stringify(helpers.normalizePolicyDocument(response.policy)), JSON.stringify(policy));
});

test('API keys expose only a masked head/tail fragment, never the full secret', async () => {
  const cases = [
    ['sk-proj-a1B2c3D4e5F6g7H8i9J0kLmN', 'sk-proj••••••kLmN'],
    ['sk-a1B2c3D4e5F6g7H8i9J0kLmNoPqR', 'sk-a1B2••••••oPqR'],
    ['sk-a1B2c3D4e5F6g7H8', 'sk-a1B••••••7H8'],
    ['plainkey123', 'pl••••••23'],
    ['short', '••••••']
  ];
  const helpers = load(() => ({ 'api-keys': cases.map(([key]) => key) }));
  const keys = await helpers.fetchCurrentKeys();
  assert.equal(JSON.stringify(keys.map((key) => key.mask)), JSON.stringify(cases.map(([, mask]) => mask)));
  for (const [index, [raw]] of cases.entries()) {
    assert.ok(!JSON.stringify(keys[index]).includes(raw), 'full key must not survive in key metadata');
    assert.ok(keys[index].mask.replaceAll('•', '').length <= Math.ceil(raw.length / 2));
  }
});

test('i18n: zh-CN and en expose the same message keys and placeholders', () => {
  const { MESSAGES } = load();
  const zh = Object.keys(MESSAGES['zh-CN']).sort();
  assert.deepEqual(Object.keys(MESSAGES.en).sort(), zh);
  const html = readFileSync(join(__dirname, 'settings.html'), 'utf8');
  for (const [, key] of html.matchAll(/data-i18n(?:-[a-z-]+)?="([^"]+)"/g)) assert.ok(zh.includes(key), key);
  for (const key of zh) {
    const zhEntry = MESSAGES['zh-CN'][key];
    const enEntry = MESSAGES.en[key];
    if (typeof zhEntry !== 'string' || typeof enEntry !== 'string') continue;
    const names = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    assert.deepEqual(names(enEntry), names(zhEntry), key);
  }
});

test('i18n: follows CPAMC language, then browser, defaulting to English', () => {
  const storage = (value) => ({ getItem: (name) => (name === 'cli-proxy-language' ? value : null) });
  const nav = (languages) => ({ languages, language: languages[0] });
  const en = load(undefined, { localStorage: storage(JSON.stringify({ state: { language: 'en' } })), navigator: nav(['zh-CN']) });
  assert.equal(en.getLocale(), 'en');
  assert.equal(en.t('rules.count', { count: 1 }), '1 rule');
  assert.equal(en.t('rules.count', { count: 3 }), '3 rules');
  assert.equal(en.t('error.http', { status: 500 }), 'Request failed (HTTP 500)');
  const zh = load(undefined, { localStorage: storage(null), navigator: nav(['zh-TW', 'en']) });
  assert.equal(zh.getLocale(), 'zh-CN');
  assert.equal(zh.t('rules.count', { count: 3 }), '3 条规则');
  assert.equal(load(undefined, { localStorage: storage(null), navigator: nav(['fr-FR']) }).getLocale(), 'en');
});
