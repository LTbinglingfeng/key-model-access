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
function load(respond = () => { throw new Error('Unexpected fetch'); }) {
  const context = vm.createContext({
    document: { querySelector: () => null },
    window: { setTimeout, clearTimeout },
    AbortController, TextEncoder,
    fetch: async (path, options) => ({ ok: true, json: async () => respond(path, options) })
  });
  vm.runInContext(source.slice(0, source.indexOf(marker)) +
    'globalThis.helpers = { pluginsDirFromList, initializeDefaultPersistence, fetchCurrentKeys, api, normalizePolicyDocument }; })();', context);
  return context.helpers;
}

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
