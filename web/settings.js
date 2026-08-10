(() => {
  "use strict";

  const PATHS = {
    status: "/v0/management/plugins/key-model-access/status",
    policies: "/v0/management/plugins/key-model-access/policies",
    reload: "/v0/management/plugins/key-model-access/reload",
    initializeStorage: "/v0/management/plugins/key-model-access/initialize-storage",
    pluginList: "/v0/management/plugins",
    pluginConfig: "/v0/management/plugins/key-model-access/config",
    apiKeys: "/v0/management/api-keys",
    apiKeyAliases: "/v0/management/api-key-aliases",
    models: "/v1/models"
  };

  const CPAMC_AUTH_KEY = "cli-proxy-auth";
  const CPAMC_THEME_KEY = "cli-proxy-theme";
  const OBFUSCATION_PREFIX = "enc::v1::";
  const OBFUSCATION_SALT = "cli-proxy-api-webui::secure-storage";

  const icons = {
    search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>',
    overview: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M15 12v2"/></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M20 6v5h-5M4 18v-5h5"/><path d="M6.1 8.2A7 7 0 0 1 18.8 9M17.9 15.8A7 7 0 0 1 5.2 15"/></svg>',
    file: '<svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>',
    save: '<svg viewBox="0 0 24 24"><path d="M5 4h12l2 2v14H5z"/><path d="M8 4v6h8V4M8 20v-6h8v6"/></svg>',
    close: '<svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4M12 16.5h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
    spinner: '<svg class="spinner" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-9 9"/><path d="M3 12a9 9 0 0 1 9-9" opacity=".35"/></svg>'
  };

  const state = {
    token: "",
    status: null,
    keys: [],
    aliasByHash: {},
    models: [],
    modelsError: "",
    persistenceSetupError: "",
    stalePolicies: [],
    revision: 0,
    selectedIndex: -1,
    dirty: false,
    busy: false,
    modelBusy: false,
    sessionBusy: false,
    sessionEnded: false,
    pendingDraft: null,
    pendingScope: "",
    search: "",
    openPicker: "",
    pickerQuery: "",
    pickerScroll: 0
  };

  const $ = (selector) => document.querySelector(selector);
  const authGate = $("#authGate");
  const app = $("#app");
  const editor = $("#editor");
  const nav = $("#policyNav");
  const saveButton = $("#saveButton");
  const reloadButton = $("#reloadButton");
  const refreshDataButton = $("#refreshDataButton");
  const healthBadge = $("#healthBadge");
  let navFrame = 0;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    })[character]);
  }

  // Mirrors CPAMC secureStorage v1. This is reversible obfuscation for session
  // compatibility, not cryptography and not a new security boundary.
  function decodeStoredValue(raw) {
    if (!raw || !raw.startsWith(OBFUSCATION_PREFIX)) return raw;
    const encoded = atob(raw.slice(OBFUSCATION_PREFIX.length));
    const encrypted = Uint8Array.from(encoded, (character) => character.charCodeAt(0));
    const key = new TextEncoder().encode(`${OBFUSCATION_SALT}|${window.location.host}|${navigator.userAgent}`);
    const decoded = new Uint8Array(encrypted.length);
    for (let index = 0; index < encrypted.length; index += 1) decoded[index] = encrypted[index] ^ key[index % key.length];
    return new TextDecoder().decode(decoded);
  }

  function readStoredValue(name) {
    try {
      const raw = localStorage.getItem(name);
      if (raw === null) return null;
      const decoded = decodeStoredValue(raw);
      try { return JSON.parse(decoded); } catch (_) { return decoded; }
    } catch (_) {
      return null;
    }
  }

  function readCPAMCManagementKey() {
    try {
      if (localStorage.getItem("isLoggedIn") !== "true") return "";
      const persisted = readStoredValue(CPAMC_AUTH_KEY);
      const current = persisted && typeof persisted === "object" ? persisted.state?.managementKey : "";
      if (typeof current === "string" && current.trim()) return current.trim();
      const legacy = readStoredValue("managementKey");
      return typeof legacy === "string" ? legacy.trim() : "";
    } catch (_) {
      return "";
    }
  }

  function normalizeModels(value) {
    if (!Array.isArray(value)) return [];
    return [...new Set(value.map((model) => String(model).trim()).filter(Boolean))];
  }

  function modelPatternMatches(pattern, model) {
    const source = String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
    try { return new RegExp(`^${source}$`).test(model); } catch (_) { return false; }
  }

  function normalizePolicyDocument(raw) {
    if (!raw || typeof raw !== "object" || raw.version !== 2 || !Array.isArray(raw.policies)) {
      throw new Error("插件返回了无效的 v2 策略文档。");
    }
    const seen = new Set();
    const policies = raw.policies.map((item, index) => {
      if (!item || typeof item !== "object") throw new Error(`策略 ${index + 1} 格式无效。`);
      const scope = typeof item.caller_scope === "string" ? item.caller_scope.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(scope)) throw new Error(`策略 ${index + 1} 的 caller scope 无效。`);
      if (seen.has(scope)) throw new Error(`策略 ${index + 1} 的 caller scope 重复。`);
      seen.add(scope);
      for (const field of ["allow_models", "deny_models"]) {
        if (!Array.isArray(item[field]) || item[field].some((model) => typeof model !== "string" || !model.trim())) {
          throw new Error(`策略 ${index + 1} 的 ${field} 无效。`);
        }
      }
      return {
        caller_scope: scope,
        allow_models: normalizeModels(item.allow_models),
        deny_models: normalizeModels(item.deny_models)
      };
    });
    return { version: 2, policies };
  }

  function shortFingerprint(scope) {
    return `${scope.slice(0, 10)}…${scope.slice(-6)}`;
  }

  function keyLabel(index) {
    return `CPA API Key ${String(index + 1).padStart(2, "0")}`;
  }

  function maskApiKey(value) {
    const text = String(value || "").trim();
    if (!text) return "";
    const visible = text.length < 4 ? 1 : 2;
    const start = text.slice(0, visible);
    const end = text.slice(-visible);
    const maskedLength = Math.max(10 - visible * 2, 1);
    return `${start}${"*".repeat(maskedLength)}${end}`;
  }

  function keyDisplayName(key, index) {
    const alias = key?.hash && state.aliasByHash[key.hash] ? state.aliasByHash[key.hash] : "";
    return alias || keyLabel(index);
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const timeout = options.timeout || (method === "GET" ? 12000 : 20000);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {
        ...options,
        method,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${state.token}`,
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(options.headers || {})
        },
        cache: "no-store"
      });
      let payload = null;
      try { payload = await response.json(); } catch (_) { payload = null; }
      if (!response.ok) {
        const detail = payload && (payload.error?.message || payload.error);
        const error = new Error(detail ? String(detail) : `请求失败（HTTP ${response.status}）`);
        error.status = response.status;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") {
        const timeoutError = new Error(method === "GET" ? "CPA 响应超时，请检查服务状态。" : "操作响应超时，提交结果尚未确认。");
        timeoutError.code = "timeout";
        throw timeoutError;
      }
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(value);
    if (window.crypto?.subtle) {
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    // SubtleCrypto is unavailable on plain HTTP origins other than localhost.
    // Keep remote CPA panels functional without sending raw API keys elsewhere.
    return sha256FallbackHex(bytes);
  }

  function sha256FallbackHex(bytes) {
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const stateWords = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const bitLength = bytes.length * 8;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(paddedLength - 4, bitLength >>> 0, false);
    const words = new Uint32Array(64);
    const rotateRight = (word, count) => (word >>> count) | (word << (32 - count));

    for (let offset = 0; offset < paddedLength; offset += 64) {
      for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4, false);
      for (let index = 16; index < 64; index += 1) {
        const left = words[index - 15];
        const right = words[index - 2];
        const sigma0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
        const sigma1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
        words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = stateWords;
      for (let index = 0; index < 64; index += 1) {
        const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        const choose = (e & f) ^ (~e & g);
        const temp1 = (h + sum1 + choose + constants[index] + words[index]) >>> 0;
        const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (sum0 + majority) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      stateWords[0] = (stateWords[0] + a) >>> 0;
      stateWords[1] = (stateWords[1] + b) >>> 0;
      stateWords[2] = (stateWords[2] + c) >>> 0;
      stateWords[3] = (stateWords[3] + d) >>> 0;
      stateWords[4] = (stateWords[4] + e) >>> 0;
      stateWords[5] = (stateWords[5] + f) >>> 0;
      stateWords[6] = (stateWords[6] + g) >>> 0;
      stateWords[7] = (stateWords[7] + h) >>> 0;
    }
    return stateWords.map((word) => word.toString(16).padStart(8, "0")).join("");
  }

  async function fetchModelCatalog(apiKey) {
    if (!apiKey) return { models: [], error: "CPA 当前没有可用于读取模型目录的 API Key。" };
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(PATHS.models, {
        method: "GET",
        headers: { Accept: "application/json", Authorization: `Bearer ${apiKey}` },
        signal: controller.signal,
        cache: "no-store"
      });
      let payload = null;
      try { payload = await response.json(); } catch (_) { payload = null; }
      if (!response.ok) throw new Error(`模型目录请求失败（HTTP ${response.status}）`);
      const source = Array.isArray(payload) ? payload : Array.isArray(payload?.data) ? payload.data : Array.isArray(payload?.models) ? payload.models : [];
      const seen = new Set();
      const models = source.map((item) => {
        if (typeof item === "string") return { id: item, displayName: "" };
        if (!item || typeof item !== "object") return null;
        const id = String(item.id ?? item.name ?? item.model ?? item.value ?? "").trim();
        const displayName = String(item.display_name ?? item.displayName ?? item.alias ?? "").trim();
        return id ? { id, displayName: displayName === id ? "" : displayName } : null;
      }).filter((item) => {
        if (!item) return false;
        const key = item.id.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      }).sort((left, right) => left.id.localeCompare(right.id));
      return { models, error: models.length ? "" : "CPA 的 /v1/models 暂未返回可用模型。" };
    } catch (error) {
      const message = error.name === "AbortError" ? "模型目录加载超时。" : error.message;
      return { models: [], error: message || "模型目录加载失败。" };
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function fetchApiKeyAliases() {
    try {
      const payload = await api(PATHS.apiKeyAliases, { method: "GET" });
      const items = Array.isArray(payload?.items) ? payload.items : [];
      const aliasByHash = {};
      for (const item of items) {
        const hash = typeof item?.apiKeyHash === "string" ? item.apiKeyHash.trim().toLowerCase() : "";
        const alias = typeof item?.alias === "string" ? item.alias.trim() : "";
        if (hash && alias) aliasByHash[hash] = alias;
      }
      return aliasByHash;
    } catch (_) {
      return {};
    }
  }

  async function fetchCurrentKeys(options = {}) {
    const payload = await api(PATHS.apiKeys, { method: "GET" });
    const values = Array.isArray(payload?.["api-keys"]) ? payload["api-keys"] : null;
    if (!values) throw new Error("CPA 返回了无法识别的 API Key 列表。");

    const temporaryValues = values.slice();
    const normalizedValues = temporaryValues.map((value) => String(value).trim()).filter(Boolean);
    try {
      const [keyDetails, catalog] = await Promise.all([
        Promise.all(normalizedValues.map(async (value) => ({
          scope: await sha256Hex(`cli-proxy-api:caller-scope:v1\0${value}`),
          hash: (await sha256Hex(value)).toLowerCase(),
          mask: maskApiKey(value)
        }))),
        options.includeCatalog ? fetchModelCatalog(normalizedValues[0] || "") : Promise.resolve(null)
      ]);
      const seen = new Set();
      const keys = keyDetails.filter(({ scope }) => {
        if (seen.has(scope)) return false;
        seen.add(scope);
        return true;
      }).map(({ scope, hash, mask }) => ({
        scope,
        hash,
        mask,
        fingerprint: shortFingerprint(scope),
        allow_models: [],
        deny_models: []
      }));
      return options.includeCatalog ? { keys, catalog } : keys;
    } finally {
      normalizedValues.fill("");
      temporaryValues.fill("");
      values.fill("");
    }
  }

  async function waitForPersistentStatus(expectedPath) {
    let lastError = null;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (attempt > 0) await new Promise((resolve) => window.setTimeout(resolve, 250));
      try {
        const status = await api(PATHS.status, { method: "GET", timeout: 1500 });
        if (status?.persistent_updates && status.policy_file === expectedPath) return status;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("CPA 已保存插件配置，但等待策略文件生效超时。");
  }

  async function initializeDefaultPersistence() {
    const pluginList = await api(PATHS.pluginList, { method: "GET" });
    const pluginsDir = typeof pluginList?.plugins_dir === "string" ? pluginList.plugins_dir.trim() : "";
    if (!pluginsDir) throw new Error("CPA 未返回有效的 plugins_dir。");
    const initialized = await api(PATHS.initializeStorage, {
      method: "POST",
      body: JSON.stringify({ plugins_dir: pluginsDir })
    });
    const policyFile = typeof initialized?.policy_file === "string" ? initialized.policy_file.trim() : "";
    if (!policyFile) throw new Error("插件未返回默认策略文件路径。");
    await api(PATHS.pluginConfig, {
      method: "PATCH",
      body: JSON.stringify({ policy_file: policyFile })
    });
    return waitForPersistentStatus(policyFile);
  }

  async function fetchRemoteData() {
    // Verify Management authentication once before issuing the remaining reads.
    let status = await api(PATHS.status, { method: "GET" });
    let persistenceSetupError = "";
    if (!status?.persistent_updates) {
      try {
        status = await initializeDefaultPersistence();
      } catch (error) {
        persistenceSetupError = error.message || "自动创建插件策略文件失败。";
      }
    }
    const [policies, keyData, aliasByHash] = await Promise.all([
      api(PATHS.policies, { method: "GET" }),
      fetchCurrentKeys({ includeCatalog: true }),
      fetchApiKeyAliases()
    ]);
    return { status, policies, keys: keyData.keys, catalog: keyData.catalog, aliasByHash, persistenceSetupError };
  }

  function applyPolicyDocument(rawDocument) {
    const documentValue = normalizePolicyDocument(rawDocument);
    const byScope = new Map(documentValue.policies.map((policy) => [policy.caller_scope, policy]));
    const currentScopes = new Set(state.keys.map((key) => key.scope));

    state.keys = state.keys.map((key) => {
      const policy = byScope.get(key.scope);
      return {
        ...key,
        allow_models: policy ? [...policy.allow_models] : [],
        deny_models: policy ? [...policy.deny_models] : []
      };
    });
    state.stalePolicies = documentValue.policies
      .filter((policy) => !currentScopes.has(policy.caller_scope))
      .map((policy) => ({ ...policy, allow_models: [...policy.allow_models], deny_models: [...policy.deny_models] }));
  }

  function installRemoteData(remote, preferredScope = "") {
    state.status = remote.status;
    state.aliasByHash = remote.aliasByHash || {};
    state.keys = remote.keys;
    state.models = remote.catalog?.models || [];
    state.modelsError = remote.catalog?.error || "";
    state.persistenceSetupError = remote.persistenceSetupError || "";
    applyPolicyDocument(remote.policies?.policy);
    state.revision = Number(remote.policies?.revision ?? remote.status?.revision ?? 0);
    state.dirty = false;
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    state.selectedIndex = preferredScope ? state.keys.findIndex((key) => key.scope === preferredScope) : -1;
  }

  function setSessionState(kind, title, message) {
    $("#authTitle").textContent = title;
    $("#authMessage").textContent = message;
    $("#sessionIcon").classList.toggle("error", kind === "error");
    $("#sessionIcon").innerHTML = kind === "loading" ? icons.spinner : kind === "error" ? icons.warning : icons.check;
    $("#retrySessionButton").hidden = kind !== "error";
  }

  async function connectFromCPAMC() {
    if (state.sessionBusy) return;
    const token = readCPAMCManagementKey();
    if (!token) {
      state.token = "";
      setSessionState("error", "未找到可复用的 CPAMC 会话", "自动接入要求 CPAMC 与 CPA 同源，并在登录时启用“记住密码”。请确认后返回此页面重试；插件不会要求你再次输入 Management Key。");
      return;
    }
    state.token = token;
    state.sessionBusy = true;
    setSessionState("loading", "正在接入管理会话", "正在验证 CPAMC 已保存的连接信息并加载模型策略…");
    try {
      const remote = await fetchRemoteData();
      const pendingDraft = state.pendingDraft;
      const pendingScope = state.pendingScope;
      installRemoteData(remote, pendingScope);
      if (pendingDraft) {
        applyPolicyDocument(pendingDraft);
        state.dirty = true;
        state.pendingDraft = null;
        state.pendingScope = "";
      }
      state.sessionEnded = false;
      authGate.hidden = true;
      app.hidden = false;
      renderAll();
    } catch (error) {
      state.token = "";
      const message = error.status === 401
        ? "CPAMC 保存的 Management Key 已失效。请返回 CPAMC 重新登录并启用“记住密码”。"
        : `无法连接 CPA：${error.message}`;
      setSessionState("error", "管理会话不可用", message);
    } finally {
      state.sessionBusy = false;
    }
  }

  function finalizeEndedSession() {
    if (!state.sessionEnded || state.busy || state.modelBusy) return;
    const hadDraft = state.dirty;
    if (hadDraft) {
      state.pendingDraft = serializablePolicy();
      state.pendingScope = selectedKey()?.scope || "";
    }
    state.token = "";
    state.status = null;
    state.keys = [];
    state.models = [];
    state.stalePolicies = [];
    state.dirty = false;
    state.sessionEnded = false;
    app.hidden = true;
    authGate.hidden = false;
    setSessionState("error", "CPAMC 会话已结束", hadDraft
      ? "未保存的策略草稿已保留在当前页面内存中。请重新登录；会话恢复后草稿会自动还原。"
      : "请先在 CPAMC 重新登录并启用“记住密码”，页面会自动重新接入。");
  }

  function setBusy(busy, action = "") {
    state.busy = busy;
    $("#workspace").inert = busy;
    refreshDataButton.disabled = busy || state.modelBusy;
    saveButton.disabled = busy || state.modelBusy || !state.dirty;
    reloadButton.disabled = busy || state.modelBusy || !state.status?.persistent_updates;
    saveButton.innerHTML = action === "save" && busy
      ? `${icons.spinner}<span class="label-long">正在保存</span>`
      : `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    reloadButton.innerHTML = action === "reload" && busy
      ? `${icons.spinner}<span class="label-long">正在重载</span>`
      : `${icons.file}<span class="label-long">从文件重载</span>`;
    refreshDataButton.innerHTML = action === "refresh" && busy
      ? icons.spinner
      : icons.refresh;
    if (!busy) finalizeEndedSession();
  }

  function markDirty() {
    state.dirty = true;
    syncHeader();
  }

  function renderAll() {
    renderNav();
    renderEditor();
    syncHeader();
    syncPersistence();
  }

  function syncHeader() {
    const healthy = state.status && !state.status.last_error;
    const warning = state.status?.last_error;
    healthBadge.innerHTML = `<span class="status-dot ${warning ? "warning" : healthy ? "" : "error"}"></span><span>${escapeHTML(warning ? "策略警告" : healthy ? `Schema v${state.status.schema_version || 2}` : "未连接")}</span>`;
    healthBadge.title = warning ? state.status.last_error : "插件运行正常";
    saveButton.disabled = state.busy || state.modelBusy || !state.dirty;
    reloadButton.disabled = state.busy || state.modelBusy || !state.status?.persistent_updates;
    reloadButton.title = state.status?.persistent_updates ? "从策略文件重载" : "未配置 policy_file，无法从文件重载";
    saveButton.innerHTML = `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    $("#policyCount").textContent = `${state.keys.length} 个当前 Key`;
  }

  function syncPersistence() {
    const notice = $("#persistenceNotice");
    if (!state.status) return;
    if (state.status.persistent_updates) {
      notice.className = "persistence-notice";
      notice.textContent = `策略自动保存到 ${state.status.policy_file}`;
    } else {
      notice.className = "persistence-notice warning";
      notice.textContent = state.persistenceSetupError
        ? `自动持久化失败：${state.persistenceSetupError} 当前修改仅保存在内存中。`
        : "当前为内存模式；打开页面时会自动创建插件策略文件。";
    }
  }

  function scheduleNavRender() {
    if (navFrame) return;
    navFrame = requestAnimationFrame(() => {
      navFrame = 0;
      renderNav();
    });
  }

  function renderNav() {
    const query = state.search.trim().toLowerCase();
    const visible = state.keys.map((key, index) => ({ key, index })).filter(({ key, index }) =>
      !query
        || keyDisplayName(key, index).toLowerCase().includes(query)
        || key.mask.toLowerCase().includes(query)
        || key.fingerprint.toLowerCase().includes(query)
        || keyLabel(index).toLowerCase().includes(query)
    );
    nav.innerHTML = `
      <button class="nav-item" type="button" data-select="overview" aria-current="${state.selectedIndex < 0 ? "page" : "false"}">
        <span class="nav-icon">${icons.overview}</span>
        <span class="nav-copy"><strong>权限概览</strong><span>认证由 CPA 管理</span></span>
      </button>
      <p class="nav-group-label">当前 CPA API Keys</p>
      ${visible.length ? visible.map(({ key, index }) => `
        <button class="nav-item" type="button" data-select="key" data-index="${index}" aria-current="${state.selectedIndex === index ? "page" : "false"}" aria-label="${escapeHTML(keyDisplayName(key, index))}，Key ${escapeHTML(key.mask)}，SHA-256 指纹 ${escapeHTML(key.fingerprint)}">
          <span class="nav-icon key">${icons.key}</span>
          <span class="nav-copy"><strong>${escapeHTML(keyDisplayName(key, index))}</strong><span>Key ${escapeHTML(key.mask)} · SHA-256 ${escapeHTML(key.fingerprint)}</span></span>
        </button>`).join("") : `<p class="empty-nav">${query ? "没有匹配的 Key" : "CPA 当前没有 API Key"}</p>`}
    `;
  }

  function renderEditor() {
    if (state.selectedIndex >= 0 && state.keys[state.selectedIndex]) {
      renderKeyEditor(state.keys[state.selectedIndex], state.selectedIndex);
      return;
    }
    state.selectedIndex = -1;
    renderOverview();
  }

  function hasRules(key) {
    return key.allow_models.length > 0 || key.deny_models.length > 0;
  }

  function renderOverview() {
    const configured = state.keys.filter(hasRules).length;
    const defaults = state.keys.length - configured;
    const staleCount = state.stalePolicies.length;
    const statusWarning = state.status?.last_error
      ? `<div class="notice">${icons.warning}<span><strong>最近一次配置存在问题：</strong> ${escapeHTML(state.status.last_error)}。当前仍在使用最后一个有效策略。</span></div>`
      : "";
    const staleWarning = staleCount
      ? `<div class="notice">${icons.warning}<span><strong>${staleCount} 条失效策略：</strong>这些 caller scope 不对应 CPA 当前 Key。保存时会原样保留，不会静默删除；请在确认旧 Key 已永久移除后通过策略文件处理。</span></div>`
      : "";

    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Access overview</p>
          <h1>模型权限概览</h1>
          <p class="editor-subtitle">API Key 的创建、删除和生命周期完全由 CPA 管理；此页面只为现有 Key 配置模型规则。</p>
        </div>
      </header>
      ${statusWarning}
      ${staleWarning}
      <section class="overview-grid" aria-label="权限统计">
        ${statCard("当前 CPA Key", state.keys.length, "只读同步")}
        ${statCard("已配置", configured, "含 allow 或 deny")}
        ${statCard("默认允许", defaults, "没有模型规则")}
        ${statCard("失效策略", staleCount, "保存时仍保留", staleCount > 0)}
      </section>
      <section class="card">
        <div class="card-head"><h2>认证边界</h2><p>Key 身份与模型授权相互分离。</p></div>
        <div class="info-callout">
          <span class="callout-icon">${icons.key}</span>
          <div><strong>认证由 CPA 内置 API Keys 管理</strong><p>插件仅接收 CPA 提供的 caller scope，并据此执行 allow_models 与 deny_models。未配置策略或规则为空时，默认允许全部模型。</p></div>
        </div>
      </section>
      <section class="card">
        <div class="card-head"><h2>运行状态</h2><p>来自当前 CPA 插件实例。</p></div>
        ${statusRow("认证模式", displayAuthMode(state.status?.auth_mode))}
        ${statusRow("身份来源", state.status?.identity_source || "—")}
        ${statusRow("未配置 Key", state.status?.unconfigured_key_action === "allow" ? "允许全部模型" : state.status?.unconfigured_key_action || "—")}
        ${statusRow("后端策略数", state.status?.policy_count ?? "—")}
        ${statusRow("策略版本", `rev-${state.revision}`)}
        ${statusRow("策略来源", state.status?.source || "—")}
        ${statusRow("最后更新", formatDate(state.status?.updated_at))}
      </section>`;
  }

  function statCard(label, value, note, warning = false) {
    return `<article class="stat-card ${warning ? "warning" : ""}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong><small>${escapeHTML(note)}</small></article>`;
  }

  function displayAuthMode(value) {
    return value === "cpa_builtin_api_keys" ? "CPA 内置 API Keys" : value || "—";
  }

  function statusRow(label, value) {
    return `<div class="setting-row"><div class="setting-copy"><strong>${escapeHTML(label)}</strong></div><div class="setting-control mono">${escapeHTML(value)}</div></div>`;
  }

  function renderKeyEditor(key, index) {
    const empty = !hasRules(key);
    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Existing CPA key</p>
          <h1>${escapeHTML(keyLabel(index))}</h1>
          <p class="editor-subtitle key-summary"><span>${key.mask}</span><span class="mono">SHA-256 ${escapeHTML(key.fingerprint)}</span></p>
        </div>
      </header>
      ${empty ? `<div class="default-notice">${icons.check}<span><strong>当前默认允许全部模型。</strong>从目录中选择允许或拒绝模型后才会为此 Key 写入策略。</span></div>` : ""}
      <section class="card rules-card">
        <div class="card-head"><h2>模型规则</h2><p>直接从 CPA 可用模型目录中选择；拒绝规则始终优先于允许规则。</p></div>
        ${modelPicker("allow_models", "允许模型", "设置后，仅允许列表中的模型", key.allow_models, false)}
        ${modelPicker("deny_models", "拒绝模型", "命中后始终拒绝访问", key.deny_models, true)}
      </section>
      <div class="privacy-note">Management Key 复用 CPAMC 已保存的同源会话；CPA API Key 只用于计算 caller scope 与读取模型目录，不会写入 DOM、浏览器存储或 URL。</div>`;
    editor.dataset.keyIndex = String(index);
  }

  function modelPicker(kind, title, description, selectedModels, deny) {
    const selected = new Set(selectedModels);
    const wildcardRules = selectedModels.filter((model) => model.includes("*") || model.includes("?"));
    const wildcardSelected = selected.has("*");
    const matchedRuleFor = (model) => wildcardRules.find((rule) => modelPatternMatches(rule, model)) || "";
    const effectiveCatalogCount = state.models.filter((model) => selected.has(model.id) || matchedRuleFor(model.id)).length;
    const isOpen = state.openPicker === kind;
    const summary = wildcardSelected
      ? "全部模型（*，包含未来新增）"
      : state.models.length
        ? effectiveCatalogCount ? `已匹配 ${effectiveCatalogCount} / ${state.models.length} 个模型` : `从 ${state.models.length} 个模型中选择`
        : selectedModels.length ? `已保留 ${selectedModels.length} 条现有规则` : "模型目录不可用";
    const chips = selectedModels.length
      ? selectedModels.map((model) => {
          const wildcard = model.includes("*") || model.includes("?");
          const outsideCatalog = !wildcard && !state.models.some((candidate) => candidate.id === model);
          return `<span class="chip ${deny ? "deny" : ""}"><span>${escapeHTML(model)}</span>${wildcard ? '<small>通配符</small>' : outsideCatalog ? '<small>目录外</small>' : ""}<button class="chip-remove" type="button" data-action="remove-model" data-kind="${kind}" data-model="${escapeHTML(model)}" aria-label="移除此模型规则">${icons.close}</button></span>`;
        }).join("")
      : '<span class="empty-chips">尚未选择模型</span>';
    const wildcardRow = `<button class="model-option wildcard-option ${wildcardSelected ? "selected" : ""}" type="button" role="option" aria-selected="${wildcardSelected}" data-action="toggle-model" data-kind="${kind}" data-model="*" data-search="全部模型 all models wildcard *">
      <span class="model-checkbox" aria-hidden="true">${wildcardSelected ? icons.check : ""}</span>
      <span class="model-option-copy"><strong>全部模型</strong><small>${deny ? "* · 此 Key 将无法访问任何模型" : "* · 自动包含未来新增模型"}</small></span>
      <span class="model-badge">通配符</span>
    </button>`;
    const commonWildcards = ["gpt-*", "claude-*", "gemini-*", "qwen-*", "deepseek-*", "grok-*", "kimi-*", "glm-*", "minimax-*"];
    const presetRows = commonWildcards.filter((rule) => selected.has(rule) || state.models.some((model) => modelPatternMatches(rule, model.id))).map((rule) => {
      const explicit = selected.has(rule);
      const derived = wildcardSelected && !explicit;
      const checked = explicit || derived;
      const matchCount = state.models.filter((model) => modelPatternMatches(rule, model.id)).length;
      return `<button class="model-option preset-option ${checked ? "selected" : ""} ${derived ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" aria-disabled="${derived}" data-action="toggle-model" data-kind="${kind}" data-model="${rule}" data-locked="${derived}" data-search="${rule} 通配符 wildcard">
        <span class="model-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span>
        <span class="model-option-copy"><strong>${rule}</strong><small>当前匹配 ${matchCount} 个模型，并覆盖未来同前缀模型</small></span>
        <span class="model-badge">通配符</span>
      </button>`;
    }).join("");
    const rows = state.models.map((model) => {
      const explicit = selected.has(model.id);
      const matchedRule = explicit ? "" : matchedRuleFor(model.id);
      const derived = Boolean(matchedRule);
      const checked = explicit || derived;
      return `<button class="model-option ${checked ? "selected" : ""} ${derived ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" aria-disabled="${derived}" data-action="toggle-model" data-kind="${kind}" data-model="${escapeHTML(model.id)}" data-locked="${derived}" data-search="${escapeHTML(`${model.id} ${model.displayName}`.toLowerCase())}">
        <span class="model-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span>
        <span class="model-option-copy"><strong>${escapeHTML(model.id)}</strong>${model.displayName ? `<small>${escapeHTML(model.displayName)}</small>` : ""}${derived ? `<small>由 ${escapeHTML(matchedRule)} 通配符匹配</small>` : ""}</span>
        ${derived ? '<span class="model-badge">通配符</span>' : ""}
      </button>`;
    }).join("");

    return `<div class="model-editor ${deny ? "deny" : ""}">
      <div class="tag-head"><div><strong>${escapeHTML(title)}</strong><span>${escapeHTML(description)}</span></div><span class="selection-count">${selectedModels.length} 条规则</span></div>
      <button class="model-trigger ${isOpen ? "open" : ""}" type="button" data-action="toggle-picker" data-kind="${kind}" aria-expanded="${isOpen}">
        <span>${escapeHTML(summary)}</span><span class="picker-chevron" aria-hidden="true">⌄</span>
        ${state.models.length ? `<progress class="selection-meter" max="${state.models.length}" value="${effectiveCatalogCount}" aria-label="已匹配 ${effectiveCatalogCount} / ${state.models.length} 个模型"></progress>` : ""}
      </button>
      ${isOpen ? `<div class="model-panel">
        ${state.models.length ? `<div class="model-search"><span>${icons.search}</span><input type="search" data-model-search="${kind}" value="${escapeHTML(state.pickerQuery)}" autocomplete="off" placeholder="搜索模型…" aria-label="搜索${escapeHTML(title)}"></div>
        <div class="model-list" role="listbox" aria-multiselectable="true">${wildcardRow}${presetRows}${rows}<p class="model-empty" hidden>没有匹配的模型</p></div>
        <div class="model-panel-footer"><span>已匹配 ${effectiveCatalogCount} / ${state.models.length}</span><div><button type="button" data-action="select-all-models" data-kind="${kind}">全选当前目录</button><button type="button" data-action="clear-models" data-kind="${kind}">清空</button></div></div>`
        : `<div class="model-list compact" role="listbox" aria-multiselectable="true">${wildcardRow}</div><div class="catalog-notice"><span>${escapeHTML(state.modelsError || "没有可用模型目录。")}</span><button type="button" data-action="refresh-models">重新加载</button></div>`}
      </div>` : ""}
      <div class="chips">${chips}</div>
    </div>`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function selectedKey() {
    return state.selectedIndex >= 0 ? state.keys[state.selectedIndex] : null;
  }

  function validModelKind(kind) {
    return kind === "allow_models" || kind === "deny_models";
  }

  function restorePickerView(kind, focusSearch = false) {
    requestAnimationFrame(() => {
      const input = editor.querySelector(`[data-model-search="${kind}"]`);
      const list = input?.closest(".model-panel")?.querySelector(".model-list");
      if (input) filterModelPicker(input);
      if (list) list.scrollTop = state.pickerScroll;
      if (focusSearch) input?.focus({ preventScroll: true });
    });
  }

  function updateModels(kind, updater) {
    if (state.busy || !validModelKind(kind)) return;
    const key = selectedKey();
    if (!key) return;
    const currentList = editor.querySelector(`[data-model-search="${kind}"]`)?.closest(".model-panel")?.querySelector(".model-list");
    state.pickerScroll = currentList?.scrollTop || 0;
    const nextModels = normalizeModels(updater([...key[kind]]));
    if (nextModels.length === key[kind].length && nextModels.every((model, index) => model === key[kind][index])) return;
    key[kind] = nextModels;
    markDirty();
    renderEditor();
    if (state.openPicker === kind) restorePickerView(kind, true);
  }

  function filterModelPicker(input) {
    const query = input.value.trim().toLowerCase();
    state.pickerQuery = input.value;
    const panel = input.closest(".model-panel");
    if (!panel) return;
    let visible = 0;
    panel.querySelectorAll(".model-option").forEach((option) => {
      const matches = !query || option.dataset.search.includes(query);
      option.hidden = !matches;
      if (matches) visible += 1;
    });
    const empty = panel.querySelector(".model-empty");
    if (empty) empty.hidden = visible > 0;
  }

  function setModelBusy(busy) {
    state.modelBusy = busy;
    refreshDataButton.disabled = busy || state.busy;
    saveButton.disabled = busy || state.busy || !state.dirty;
    reloadButton.disabled = busy || state.busy || !state.status?.persistent_updates;
    if (!busy) finalizeEndedSession();
  }

  async function refreshModelCatalog() {
    if (state.busy || state.modelBusy) return;
    setModelBusy(true);
    const retryButton = editor.querySelector('[data-action="refresh-models"]');
    if (retryButton) { retryButton.disabled = true; retryButton.innerHTML = `${icons.spinner}<span>加载中</span>`; }
    try {
      const result = await fetchCurrentKeys({ includeCatalog: true });
      state.models = result.catalog?.models || [];
      state.modelsError = result.catalog?.error || "";
      renderEditor();
      showToast(state.models.length ? `已加载 ${state.models.length} 个模型` : state.modelsError, state.models.length ? "success" : "error");
    } finally {
      setModelBusy(false);
      syncHeader();
    }
  }

  function serializablePolicy() {
    const active = state.keys.filter(hasRules).map((key) => ({
      caller_scope: key.scope,
      allow_models: [...key.allow_models],
      deny_models: [...key.deny_models]
    }));
    const stale = state.stalePolicies.map((policy) => ({
      caller_scope: policy.caller_scope,
      allow_models: [...policy.allow_models],
      deny_models: [...policy.deny_models]
    }));
    return { version: 2, policies: [...active, ...stale] };
  }

  function scopeSet(keys) {
    return new Set(keys.map((key) => key.scope));
  }

  function setsEqual(left, right) {
    if (left.size !== right.size) return false;
    for (const value of left) if (!right.has(value)) return false;
    return true;
  }

  async function save() {
    if (!state.dirty || state.busy) return;
    const expectedRevision = state.revision;
    const submittedPolicy = serializablePolicy();
    setBusy(true, "save");
    try {
      const latestKeys = await fetchCurrentKeys();
      if (!setsEqual(scopeSet(state.keys), scopeSet(latestKeys))) {
        const changed = new Error("CPA API Key 列表已变化；为避免策略错配，保存已中止。请刷新数据后重新检查规则。");
        changed.code = "key_set_changed";
        throw changed;
      }

      const response = await api(PATHS.policies, {
        method: "PUT",
        headers: { "If-Match": `"rev-${expectedRevision}"` },
        body: JSON.stringify(submittedPolicy)
      });
      let keySetChangedAfterSave = false;
      let postSaveCheckError = null;
      try {
        const keysAfterSave = await fetchCurrentKeys();
        keySetChangedAfterSave = !setsEqual(scopeSet(state.keys), scopeSet(keysAfterSave));
        if (keySetChangedAfterSave) state.keys = keysAfterSave;
      } catch (verificationError) {
        postSaveCheckError = verificationError;
      }
      applyPolicyDocument(response?.policy || submittedPolicy);
      state.revision = Number(response?.revision ?? expectedRevision + 1);
      state.dirty = false;
      renderAll();
      if (keySetChangedAfterSave) {
        showToast("策略已保存，但 CPA Key 列表在保存期间发生变化；新 Key 当前默认允许全部模型，请立即检查。", "error");
      } else if (postSaveCheckError) {
        showToast(`策略已保存，但无法复核 CPA Key 列表：${postSaveCheckError.message}`, "error");
      } else {
        showToast(response?.persistent ? "策略已保存并持久化" : "策略已保存到内存", "success");
      }
      try {
        state.status = await api(PATHS.status, { method: "GET" });
        syncHeader();
        syncPersistence();
      } catch (refreshError) {
        showToast(`策略已保存，但状态刷新失败：${refreshError.message}`, "error");
      }
    } catch (error) {
      if (error.code === "timeout") {
        const confirmed = await confirmTimedOutSave(submittedPolicy, expectedRevision);
        showToast(confirmed ? "保存响应超时，但已重新读取并确认提交成功" : "保存结果无法确认；本地修改已保留，请刷新后核对。", confirmed ? "success" : "error");
      } else if (error.code === "key_set_changed") {
        showToast(error.message, "error", "刷新数据", refreshData);
      } else if (error.status === 412) {
        showToast("策略已被其他管理员或配置重载修改。请刷新数据后再保存。", "error", "刷新数据", refreshData);
      } else {
        showToast(error.message, "error");
      }
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function confirmTimedOutSave(submittedPolicy, expectedRevision) {
    try {
      const policies = await api(PATHS.policies, { method: "GET" });
      const remoteRevision = Number(policies?.revision ?? 0);
      if (remoteRevision <= expectedRevision || !policiesEquivalent(submittedPolicy, policies?.policy)) return false;
      applyPolicyDocument(policies.policy);
      state.revision = remoteRevision;
      state.dirty = false;
      try { state.status = await api(PATHS.status, { method: "GET" }); } catch (_) { /* policy confirmation is sufficient */ }
      renderAll();
      return true;
    } catch (_) {
      return false;
    }
  }

  function policiesEquivalent(leftRaw, rightRaw) {
    const canonical = (raw) => normalizePolicyDocument(raw).policies.map((policy) => ({
      caller_scope: policy.caller_scope,
      allow_models: [...policy.allow_models].sort(),
      deny_models: [...policy.deny_models].sort()
    })).sort((left, right) => left.caller_scope.localeCompare(right.caller_scope));
    return JSON.stringify(canonical(leftRaw)) === JSON.stringify(canonical(rightRaw));
  }

  async function refreshData() {
    if (state.busy) return;
    if (state.dirty && !window.confirm("刷新会放弃尚未保存的模型规则。是否继续？")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "refresh");
    try {
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("已刷新 CPA Key 与策略", "success");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function reload() {
    if (state.busy || !state.status?.persistent_updates) return;
    if (state.dirty && !window.confirm("从策略文件重载会放弃尚未保存的模型规则。是否继续？")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "reload");
    let reloaded = false;
    try {
      await api(PATHS.reload, { method: "POST" });
      reloaded = true;
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("已从策略文件重载", "success");
    } catch (error) {
      showToast(reloaded ? `策略已重载，但界面刷新失败：${error.message}` : error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  function showToast(message, type = "success", actionLabel = "", action = null) {
    const toast = document.createElement("div");
    toast.className = `toast ${type} enter`;
    toast.innerHTML = `${type === "error" ? icons.warning : icons.check}<span>${escapeHTML(message)}</span>${actionLabel ? `<button type="button">${escapeHTML(actionLabel)}</button>` : ""}`;
    $("#toastRegion").appendChild(toast);
    const button = toast.querySelector("button");
    let timer = window.setTimeout(remove, actionLabel ? 7000 : 3600);
    if (button) button.addEventListener("click", () => { window.clearTimeout(timer); action?.(); remove(); });
    requestAnimationFrame(() => toast.classList.remove("enter"));
    function remove() {
      if (!toast.isConnected) return;
      toast.classList.add("exit");
      window.setTimeout(() => toast.remove(), 190);
    }
  }

  function resolveCPAMCTheme() {
    try {
      if (window.self !== window.top) {
        const parentTheme = window.parent.document.documentElement.getAttribute("data-theme");
        return parentTheme === "dark" || parentTheme === "white" ? parentTheme : "light";
      }
    } catch (_) { /* same-origin storage remains the fallback */ }
    try {
      const persisted = JSON.parse(localStorage.getItem(CPAMC_THEME_KEY) || "null");
      const theme = persisted?.state?.theme;
      if (theme === "dark" || theme === "white" || theme === "light") return theme;
      if (theme === "auto") return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
    } catch (_) { /* use system preference */ }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
  }

  function syncTheme() {
    const theme = resolveCPAMCTheme();
    if (theme === "light") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = theme;
  }

  function initializeChrome() {
    document.documentElement.classList.toggle("is-embedded", window.self !== window.top);
    $("#searchIcon").innerHTML = icons.search;
    refreshDataButton.innerHTML = icons.refresh;
    reloadButton.innerHTML = `${icons.file}<span class="label-long">从文件重载</span>`;
    saveButton.innerHTML = `${icons.save}<span class="label-long">已保存</span>`;
    syncTheme();
    try {
      if (window.self !== window.top) {
        new MutationObserver(syncTheme).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
      }
    } catch (_) { /* cross-origin embedding is unsupported for session reuse */ }
  }

  $("#retrySessionButton").addEventListener("click", connectFromCPAMC);
  window.addEventListener("storage", (event) => {
    if (event.key === CPAMC_THEME_KEY) syncTheme();
    if (event.key !== CPAMC_AUTH_KEY && event.key !== "isLoggedIn") return;
    if (app.hidden) {
      connectFromCPAMC();
      return;
    }
    if (!readCPAMCManagementKey()) {
      state.sessionEnded = true;
      finalizeEndedSession();
    }
  });

  refreshDataButton.addEventListener("click", refreshData);
  saveButton.addEventListener("click", save);
  reloadButton.addEventListener("click", reload);
  $("#searchInput").addEventListener("input", (event) => { state.search = event.target.value; scheduleNavRender(); });

  nav.addEventListener("click", (event) => {
    if (state.busy) return;
    const item = event.target.closest("[data-select]");
    if (!item) return;
    state.selectedIndex = item.dataset.select === "overview" ? -1 : Number(item.dataset.index);
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    renderNav();
    renderEditor();
  });

  editor.addEventListener("click", (event) => {
    if (state.busy) return;
    const target = event.target.closest("button");
    if (!target) return;
    const action = target.dataset.action;
    const kind = target.dataset.kind;
    if (action === "toggle-picker" && validModelKind(kind)) {
      const opening = state.openPicker !== kind;
      state.openPicker = opening ? kind : "";
      if (opening) { state.pickerQuery = ""; state.pickerScroll = 0; }
      renderEditor();
      if (opening) restorePickerView(kind, true);
    } else if (action === "toggle-model") {
      if (target.dataset.locked === "true") return;
      updateModels(kind, (models) => models.includes(target.dataset.model) ? models.filter((model) => model !== target.dataset.model) : [...models, target.dataset.model]);
    } else if (action === "remove-model") {
      updateModels(kind, (models) => models.filter((model) => model !== target.dataset.model));
    } else if (action === "select-all-models") {
      updateModels(kind, (models) => [...new Set([...models, ...state.models.map((model) => model.id)])]);
    } else if (action === "clear-models") {
      updateModels(kind, () => []);
    } else if (action === "refresh-models") {
      refreshModelCatalog().catch((error) => showToast(error.message, "error"));
    }
  });

  editor.addEventListener("input", (event) => {
    if (event.target.matches("[data-model-search]")) filterModelPicker(event.target);
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s" && !app.hidden) {
      event.preventDefault();
      save();
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });

  initializeChrome();
  connectFromCPAMC();
})();
