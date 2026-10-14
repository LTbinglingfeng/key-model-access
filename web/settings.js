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
    models: "/v1/models"
  };

  const CPAMC_AUTH_KEY = "cli-proxy-auth";
  const CPAMC_THEME_KEY = "cli-proxy-theme";
  const CPAMC_LANGUAGE_KEY = "cli-proxy-language";
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
    chevronDown: '<svg viewBox="0 0 24 24"><path d="m7 10 5 5 5-5"/></svg>',
    chevronRight: '<svg viewBox="0 0 24 24"><path d="m10 7 5 5-5 5"/></svg>',
    spinner: '<svg class="spinner" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-9 9"/><path d="M3 12a9 9 0 0 1 9-9" opacity=".35"/></svg>'
  };

  const plural = (count, one, many) => (Number(count) === 1 ? one : many);

  const MESSAGES = {
    "zh-CN": {
      "meta.description": "CPA Key Model Access 设置",
      "meta.title": "模型权限 · CPA",
      "brand.title": "模型权限",
      "session.connectingTitle": "正在接入管理会话",
      "session.readingMessage": "正在读取 CPAMC 当前连接信息，无需再次输入 Management Key。",
      "session.retry": "重新读取会话",
      "session.footnote": "插件只复用 CPAMC 已保存的同源会话，不会复制或持久化 Management Key。",
      "session.noSessionTitle": "未找到可复用的 CPAMC 会话",
      "session.noSessionMessage": "自动接入要求 CPAMC 与 CPA 同源，并在登录时启用“记住密码”。请确认后返回此页面重试；插件不会要求你再次输入 Management Key。",
      "session.loadingMessage": "正在验证 CPAMC 已保存的连接信息并加载模型策略…",
      "session.expired": "CPAMC 保存的 Management Key 已失效。请返回 CPAMC 重新登录并启用“记住密码”。",
      "session.connectFailed": "无法连接 CPA：{message}",
      "session.unavailableTitle": "管理会话不可用",
      "session.endedTitle": "CPAMC 会话已结束",
      "session.endedDraft": "未保存的策略草稿已保留在当前页面内存中。请重新登录；会话恢复后草稿会自动还原。",
      "session.endedNoDraft": "请先在 CPAMC 重新登录并启用“记住密码”，页面会自动重新接入。",
      "nav.label": "策略导航",
      "nav.search": "搜索 Key",
      "nav.overview": "概览",
      "nav.noMatch": "没有匹配的 Key",
      "nav.noKeys": "CPA 当前没有 API Key",
      "list.separator": "，",
      "health.connecting": "正在连接",
      "health.warning": "策略警告",
      "health.ok": "运行正常 · rev-{revision}",
      "health.disconnected": "未连接",
      "action.reload": "从策略文件重载",
      "action.reloadUnavailable": "未配置 policy_file，无法从文件重载",
      "action.refresh": "刷新 CPA Key 与策略",
      "action.save": "保存",
      "action.saving": "保存中",
      "action.refreshData": "刷新数据",
      "savebar.label": "未保存的修改",
      "savebar.text": "有未保存的修改",
      "persist.title": "策略自动保存到 {path}",
      "persist.failed": "自动持久化失败：{error} 当前修改仅保存在内存中。",
      "persist.memory": "内存模式：修改不会写入文件。",
      "badge.default": "默认",
      "badge.allowRules": "允许规则",
      "badge.denyRules": "拒绝规则",
      "overview.title": "概览",
      "overview.subtitle": "为 CPA 现有 API Key 配置可访问的模型。Key 的创建与删除由 CPA 管理；未配置规则的 Key 默认允许全部模型。",
      "overview.lastErrorTitle": "最近一次配置存在问题",
      "overview.lastError": "{error}。当前仍在使用最后一个有效策略。",
      "overview.staleTitle": "{count} 条失效策略",
      "overview.staleBody": "这些 caller scope 不对应 CPA 当前 Key。保存时会原样保留，不会静默删除；确认旧 Key 已永久移除后，请通过策略文件处理。",
      "overview.statsLabel": "权限统计",
      "overview.configured": "已配置",
      "overview.defaultAllow": "默认允许",
      "overview.stale": "失效策略",
      "overview.status": "运行状态",
      "overview.authMode": "认证模式",
      "overview.identitySource": "身份来源",
      "overview.unconfiguredKeys": "未配置 Key",
      "overview.allowAll": "允许全部模型",
      "overview.policyCount": "后端策略数",
      "overview.revision": "策略版本",
      "overview.source": "策略来源",
      "overview.updatedAt": "最后更新",
      "overview.builtinAuth": "CPA 内置 API Keys",
      "rules.allow": "允许",
      "rules.deny": "拒绝",
      "rules.defaultAllowAll": "默认允许全部模型",
      "rules.configured": "已配置规则",
      "rules.allowDescription": "设置后，仅允许这些模型",
      "rules.denyDescription": "命中即拒绝，优先于允许规则",
      "rules.count": "{count} 条规则",
      "key.fingerprintTitle": "caller scope 指纹",
      "key.privacy": "页面只显示 Key 的首尾片段用于辨认；完整 Key 仅在内存中短暂用于计算 caller scope 与读取模型目录，不会写入页面、浏览器存储或 URL。",
      "picker.allModelsWildcard": "全部模型（*，包含未来新增）",
      "picker.matched": "已匹配 {matched} / {total} 个模型",
      "picker.chooseFrom": "从 {total} 个模型中选择",
      "picker.keptRules": "已保留 {count} 条现有规则",
      "picker.catalogUnavailable": "模型目录不可用",
      "picker.wildcard": "通配符",
      "picker.outsideCatalog": "目录外",
      "picker.removeRule": "移除此模型规则",
      "picker.noDenied": "未拒绝任何模型",
      "picker.unrestricted": "未限制，允许全部模型",
      "picker.allModels": "全部模型",
      "picker.allDenyHint": "* · 此 Key 将无法访问任何模型",
      "picker.allAllowHint": "* · 自动包含未来新增模型",
      "picker.presetHint": "当前匹配 {count} 个模型，并覆盖未来同前缀模型",
      "picker.matchedBy": "由 {rule} 通配符匹配",
      "picker.searchPlaceholder": "搜索模型…",
      "picker.searchLabel": "搜索{title}模型",
      "picker.noMatch": "没有匹配的模型",
      "picker.footerMatched": "已匹配 {matched} / {total}",
      "picker.selectAll": "全选当前目录",
      "picker.clear": "清空",
      "picker.noCatalog": "没有可用模型目录。",
      "picker.reload": "重新加载",
      "picker.loading": "加载中",
      "picker.loaded": "已加载 {count} 个模型",
      "error.invalidDocument": "插件返回了无效的 v2 策略文档。",
      "error.policyInvalid": "策略 {index} 格式无效。",
      "error.policyScopeInvalid": "策略 {index} 的 caller scope 无效。",
      "error.policyScopeDuplicate": "策略 {index} 的 caller scope 重复。",
      "error.policyFieldInvalid": "策略 {index} 的 {field} 无效。",
      "error.http": "请求失败（HTTP {status}）",
      "error.readTimeout": "CPA 响应超时，请检查服务状态。",
      "error.writeTimeout": "操作响应超时，提交结果尚未确认。",
      "error.catalogNoKey": "CPA 当前没有可用于读取模型目录的 API Key。",
      "error.catalogHttp": "模型目录请求失败（HTTP {status}）",
      "error.catalogEmpty": "CPA 的 /v1/models 暂未返回可用模型。",
      "error.catalogTimeout": "模型目录加载超时。",
      "error.catalogFailed": "模型目录加载失败。",
      "error.keysUnrecognized": "CPA 返回了无法识别的 API Key 列表。",
      "error.persistTimeout": "CPA 已保存插件配置，但等待策略文件生效超时。",
      "error.noPluginsDir": "CPA 未返回有效的 plugins_dir。",
      "error.noPolicyFile": "插件未返回默认策略文件路径。",
      "error.persistSetupFailed": "自动创建插件策略文件失败。",
      "save.keySetChanged": "CPA API Key 列表已变化；为避免策略错配，保存已中止。请刷新数据后重新检查规则。",
      "save.keysChangedAfter": "策略已保存，但 CPA Key 列表在保存期间发生变化；新 Key 当前默认允许全部模型，请立即检查。",
      "save.verifyFailed": "策略已保存，但无法复核 CPA Key 列表：{message}",
      "save.persisted": "策略已保存并持久化",
      "save.memory": "策略已保存到内存",
      "save.statusFailed": "策略已保存，但状态刷新失败：{message}",
      "save.timeoutConfirmed": "保存响应超时，但已重新读取并确认提交成功",
      "save.timeoutUnconfirmed": "保存结果无法确认；本地修改已保留，请刷新后核对。",
      "save.conflict": "策略已被其他管理员或配置重载修改。请刷新数据后再保存。",
      "refresh.confirm": "刷新会放弃尚未保存的模型规则。是否继续？",
      "refresh.done": "已刷新 CPA Key 与策略",
      "reload.confirm": "从策略文件重载会放弃尚未保存的模型规则。是否继续？",
      "reload.done": "已从策略文件重载",
      "reload.uiFailed": "策略已重载，但界面刷新失败：{message}"
    },
    en: {
      "meta.description": "CPA Key Model Access settings",
      "meta.title": "Model Access · CPA",
      "brand.title": "Model Access",
      "session.connectingTitle": "Connecting to management session",
      "session.readingMessage": "Reading the current CPAMC connection. There is no need to enter the Management Key again.",
      "session.retry": "Retry session",
      "session.footnote": "The plugin only reuses the same-origin session saved by CPAMC and never copies or persists the Management Key.",
      "session.noSessionTitle": "No reusable CPAMC session found",
      "session.noSessionMessage": "Automatic sign-in requires CPAMC and CPA to share the same origin, with “Remember password” enabled at login. Check this and retry here; the plugin will never ask you to re-enter the Management Key.",
      "session.loadingMessage": "Verifying the saved CPAMC connection and loading model policies…",
      "session.expired": "The Management Key saved by CPAMC is no longer valid. Sign in to CPAMC again with “Remember password” enabled.",
      "session.connectFailed": "Unable to connect to CPA: {message}",
      "session.unavailableTitle": "Management session unavailable",
      "session.endedTitle": "CPAMC session ended",
      "session.endedDraft": "Your unsaved policy draft is kept in this page's memory. Sign in again and it will be restored automatically.",
      "session.endedNoDraft": "Sign in to CPAMC again with “Remember password” enabled; this page will reconnect automatically.",
      "nav.label": "Policy navigation",
      "nav.search": "Search keys",
      "nav.overview": "Overview",
      "nav.noMatch": "No matching keys",
      "nav.noKeys": "CPA has no API keys yet",
      "list.separator": ", ",
      "health.connecting": "Connecting",
      "health.warning": "Policy warning",
      "health.ok": "Healthy · rev-{revision}",
      "health.disconnected": "Disconnected",
      "action.reload": "Reload from policy file",
      "action.reloadUnavailable": "policy_file is not configured; cannot reload from file",
      "action.refresh": "Refresh CPA keys and policies",
      "action.save": "Save",
      "action.saving": "Saving",
      "action.refreshData": "Refresh data",
      "savebar.label": "Unsaved changes",
      "savebar.text": "You have unsaved changes",
      "persist.title": "Policies are saved automatically to {path}",
      "persist.failed": "Automatic persistence failed: {error} Changes are kept in memory only.",
      "persist.memory": "Memory mode: changes are not written to a file.",
      "badge.default": "Default",
      "badge.allowRules": "Allow rules",
      "badge.denyRules": "Deny rules",
      "overview.title": "Overview",
      "overview.subtitle": "Configure which models each existing CPA API key can access. Keys are created and deleted in CPA; keys without rules can access all models by default.",
      "overview.lastErrorTitle": "The latest configuration has a problem",
      "overview.lastError": "{error}. The last valid policy is still in effect.",
      "overview.staleTitle": ({ count }) => `${count} stale ${plural(count, "policy", "policies")}`,
      "overview.staleBody": "These caller scopes don't match any current CPA key. They are kept as-is on save and never silently deleted; once you have confirmed the old keys are permanently removed, clean them up in the policy file.",
      "overview.statsLabel": "Access statistics",
      "overview.configured": "Configured",
      "overview.defaultAllow": "Default allow",
      "overview.stale": "Stale policies",
      "overview.status": "Runtime status",
      "overview.authMode": "Auth mode",
      "overview.identitySource": "Identity source",
      "overview.unconfiguredKeys": "Unconfigured keys",
      "overview.allowAll": "Allow all models",
      "overview.policyCount": "Backend policies",
      "overview.revision": "Policy revision",
      "overview.source": "Policy source",
      "overview.updatedAt": "Last updated",
      "overview.builtinAuth": "CPA built-in API keys",
      "rules.allow": "Allow",
      "rules.deny": "Deny",
      "rules.defaultAllowAll": "All models allowed by default",
      "rules.configured": "Rules configured",
      "rules.allowDescription": "When set, only these models are allowed",
      "rules.denyDescription": "Matching models are denied, overriding allow rules",
      "rules.count": ({ count }) => `${count} ${plural(count, "rule", "rules")}`,
      "key.fingerprintTitle": "caller scope fingerprint",
      "key.privacy": "Only the first and last characters of each key are shown for identification. The full key is held in memory only briefly to compute the caller scope and read the model catalog, and is never written to the page, browser storage, or URLs.",
      "picker.allModelsWildcard": "All models (*, including future ones)",
      "picker.matched": ({ matched, total }) => `${matched} / ${total} ${plural(total, "model", "models")} matched`,
      "picker.chooseFrom": ({ total }) => `Choose from ${total} ${plural(total, "model", "models")}`,
      "picker.keptRules": ({ count }) => `${count} existing ${plural(count, "rule", "rules")} kept`,
      "picker.catalogUnavailable": "Model catalog unavailable",
      "picker.wildcard": "Wildcard",
      "picker.outsideCatalog": "Not in catalog",
      "picker.removeRule": "Remove this model rule",
      "picker.noDenied": "No models denied",
      "picker.unrestricted": "Unrestricted, all models allowed",
      "picker.allModels": "All models",
      "picker.allDenyHint": "* · This key will not be able to access any model",
      "picker.allAllowHint": "* · Automatically includes future models",
      "picker.presetHint": ({ count }) => `Matches ${count} ${plural(count, "model", "models")} now, plus future models with this prefix`,
      "picker.matchedBy": "Matched by wildcard {rule}",
      "picker.searchPlaceholder": "Search models…",
      "picker.searchLabel": ({ title }) => `Search models to ${String(title).toLowerCase()}`,
      "picker.noMatch": "No matching models",
      "picker.footerMatched": "{matched} / {total} matched",
      "picker.selectAll": "Select entire catalog",
      "picker.clear": "Clear",
      "picker.noCatalog": "No model catalog available.",
      "picker.reload": "Reload",
      "picker.loading": "Loading",
      "picker.loaded": ({ count }) => `Loaded ${count} ${plural(count, "model", "models")}`,
      "error.invalidDocument": "The plugin returned an invalid v2 policy document.",
      "error.policyInvalid": "Policy {index} is malformed.",
      "error.policyScopeInvalid": "Policy {index} has an invalid caller scope.",
      "error.policyScopeDuplicate": "Policy {index} has a duplicate caller scope.",
      "error.policyFieldInvalid": "Policy {index} has an invalid {field}.",
      "error.http": "Request failed (HTTP {status})",
      "error.readTimeout": "CPA did not respond in time. Please check the service status.",
      "error.writeTimeout": "The operation timed out; its result has not been confirmed.",
      "error.catalogNoKey": "CPA has no API Key available to read the model catalog.",
      "error.catalogHttp": "Model catalog request failed (HTTP {status})",
      "error.catalogEmpty": "CPA's /v1/models returned no available models.",
      "error.catalogTimeout": "Loading the model catalog timed out.",
      "error.catalogFailed": "Failed to load the model catalog.",
      "error.keysUnrecognized": "CPA returned an unrecognized API Key list.",
      "error.persistTimeout": "CPA saved the plugin config, but timed out waiting for the policy file to take effect.",
      "error.noPluginsDir": "CPA did not return a valid plugins_dir.",
      "error.noPolicyFile": "The plugin did not return a default policy file path.",
      "error.persistSetupFailed": "Failed to create the plugin policy file automatically.",
      "save.keySetChanged": "The CPA API Key list has changed; saving was aborted to avoid mismatched policies. Refresh the data and review the rules again.",
      "save.keysChangedAfter": "Policies saved, but the CPA key list changed during the save; new keys currently allow all models. Review them now.",
      "save.verifyFailed": "Policies saved, but the CPA key list could not be re-verified: {message}",
      "save.persisted": "Policies saved and persisted",
      "save.memory": "Policies saved to memory",
      "save.statusFailed": "Policies saved, but refreshing the status failed: {message}",
      "save.timeoutConfirmed": "The save timed out, but a re-read confirmed it succeeded",
      "save.timeoutUnconfirmed": "The save result could not be confirmed; local changes are kept. Refresh and verify.",
      "save.conflict": "Policies were changed by another administrator or a config reload. Refresh the data before saving.",
      "refresh.confirm": "Refreshing discards unsaved model rules. Continue?",
      "refresh.done": "CPA keys and policies refreshed",
      "reload.confirm": "Reloading from the policy file discards unsaved model rules. Continue?",
      "reload.done": "Reloaded from policy file",
      "reload.uiFailed": "Policies reloaded, but refreshing the UI failed: {message}"
    }
  };

  function normalizeLocale(value) {
    const tag = String(value || "").trim().toLowerCase();
    if (!tag) return "";
    if (tag.startsWith("zh")) return "zh-CN";
    if (tag.startsWith("en")) return "en";
    return "";
  }

  // Follow the CPAMC UI language (embedding document, then its persisted store),
  // then the browser preference. Anything unsupported falls back to English.
  function detectLocale() {
    try {
      if (window.self !== window.top) {
        const parentLocale = normalizeLocale(window.parent.document.documentElement.getAttribute("lang"));
        if (parentLocale) return parentLocale;
      }
    } catch (_) { /* storage and browser preference remain the fallback */ }
    const stored = readStoredValue(CPAMC_LANGUAGE_KEY);
    const preferred = normalizeLocale(stored && typeof stored === "object" ? stored.state?.language ?? stored.language : stored)
      || normalizeLocale(readStoredValue("i18nextLng"));
    if (preferred) return preferred;
    if (typeof navigator !== "undefined") {
      for (const language of [...(navigator.languages || []), navigator.language]) {
        const match = normalizeLocale(language);
        if (match) return match;
      }
      return "en";
    }
    return "zh-CN";
  }

  let locale = detectLocale();

  function t(key, params = {}) {
    const entry = MESSAGES[locale]?.[key] ?? MESSAGES["zh-CN"][key];
    if (entry === undefined) return key;
    if (typeof entry === "function") return entry(params);
    return entry.replace(/\{(\w+)\}/g, (match, name) => (name in params ? String(params[name]) : match));
  }

  function applyStaticTranslations() {
    document.documentElement.lang = locale;
    document.title = t("meta.title");
    document.querySelector('meta[name="description"]')?.setAttribute("content", t("meta.description"));
    document.querySelectorAll("[data-i18n]").forEach((element) => { element.textContent = t(element.dataset.i18n); });
    for (const attribute of ["aria-label", "title", "placeholder"]) {
      document.querySelectorAll(`[data-i18n-${attribute}]`).forEach((element) => {
        element.setAttribute(attribute, t(element.getAttribute(`data-i18n-${attribute}`)));
      });
    }
  }

  const state = {
    sessionView: null,
    token: "",
    status: null,
    keys: [],
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
    pickerScroll: 0,
    pickerAnimate: ""
  };

  const $ = (selector) => document.querySelector(selector);
  const authGate = $("#authGate");
  const app = $("#app");
  const editor = $("#editor");
  const nav = $("#policyNav");
  const saveButton = $("#saveButton");
  const saveBar = $("#saveBar");
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
      throw new Error(t("error.invalidDocument"));
    }
    const seen = new Set();
    const policies = raw.policies.map((item, index) => {
      if (!item || typeof item !== "object") throw new Error(t("error.policyInvalid", { index: index + 1 }));
      const scope = typeof item.caller_scope === "string" ? item.caller_scope.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(scope)) throw new Error(t("error.policyScopeInvalid", { index: index + 1 }));
      if (seen.has(scope)) throw new Error(t("error.policyScopeDuplicate", { index: index + 1 }));
      seen.add(scope);
      for (const field of ["allow_models", "deny_models"]) {
        if (!Array.isArray(item[field]) || item[field].some((model) => typeof model !== "string" || !model.trim())) {
          throw new Error(t("error.policyFieldInvalid", { index: index + 1, field }));
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
        const error = new Error(detail ? String(detail) : t("error.http", { status: response.status }));
        error.status = response.status;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") {
        const timeoutError = new Error(t(method === "GET" ? "error.readTimeout" : "error.writeTimeout"));
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
    if (!apiKey) return { models: [], error: t("error.catalogNoKey") };
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
      if (!response.ok) throw new Error(t("error.catalogHttp", { status: response.status }));
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
      return { models, error: models.length ? "" : t("error.catalogEmpty") };
    } catch (error) {
      const message = error.name === "AbortError" ? t("error.catalogTimeout") : error.message;
      return { models: [], error: message || t("error.catalogFailed") };
    } finally {
      window.clearTimeout(timer);
    }
  }

  // Only a short head/tail fragment ever leaves this function — enough to tell keys
  // apart the way CPAMC and other consoles do, never enough to use them. Short keys
  // reveal proportionally less so a fragment can never approach the full secret.
  function maskKey(value) {
    const key = String(value || "");
    if (key.length < 8) return "••••••";
    if (key.length < 16) return `${key.slice(0, 2)}••••••${key.slice(-2)}`;
    const prefix = /^[A-Za-z]{2,4}-/.exec(key)?.[0] || "";
    const visible = key.length < 24 ? 3 : 4;
    return `${key.slice(0, prefix.length + visible)}••••••${key.slice(-visible)}`;
  }

  async function fetchCurrentKeys(options = {}) {
    const payload = await api(PATHS.apiKeys, { method: "GET" });
    const rawKeys = payload?.["api-keys"];
    const values = rawKeys === null ? [] : Array.isArray(rawKeys) ? rawKeys : null;
    if (!values) throw new Error(t("error.keysUnrecognized"));

    const temporaryValues = values.slice();
    const normalizedValues = temporaryValues.map((value) => String(value).trim()).filter(Boolean);
    try {
      const [scopes, catalog] = await Promise.all([
        Promise.all(normalizedValues.map((value) => sha256Hex(`cli-proxy-api:caller-scope:v1\0${value}`))),
        options.includeCatalog ? fetchModelCatalog(normalizedValues[0] || "") : Promise.resolve(null)
      ]);
      const seen = new Set();
      const keys = [];
      scopes.forEach((scope, index) => {
        if (seen.has(scope)) return;
        seen.add(scope);
        keys.push({
          scope,
          fingerprint: shortFingerprint(scope),
          mask: maskKey(normalizedValues[index]),
          allow_models: [],
          deny_models: []
        });
      });
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
    throw lastError || new Error(t("error.persistTimeout"));
  }

  function pluginsDirFromList(pluginList) {
    // Only /v0/management/plugins.plugins_dir uses Go html.EscapeString.
    // Replace its five entities in one pass, preserving escaped entity literals.
    // Legacy hosts with raw entity literals in directory names are ambiguous;
    // this follows the current host contract, not heuristic/version detection.
    // Do not add a raw-config fallback here: YAML needs parsing, while JSON
    // config adds a separate contract/read; server-side path/default/~ resolution
    // from the list endpoint remains authoritative.
    const value = typeof pluginList?.plugins_dir === "string" ? pluginList.plugins_dir.trim() : "";
    return value.replace(/&(?:amp|lt|gt|#34|#39);/g, (entity) => ({
      "&amp;": "&", "&lt;": "<", "&gt;": ">", "&#34;": '"', "&#39;": "'"
    })[entity]);
  }

  async function initializeDefaultPersistence() {
    const pluginList = await api(PATHS.pluginList, { method: "GET" });
    const pluginsDir = pluginsDirFromList(pluginList);
    if (!pluginsDir) throw new Error(t("error.noPluginsDir"));
    const initialized = await api(PATHS.initializeStorage, {
      method: "POST",
      body: JSON.stringify({ plugins_dir: pluginsDir })
    });
    // Plugin RPC6 responses are raw on both legacy host2 and current host6.
    // Never entity-decode policy paths (or other plugin response fields).
    const policyFile = typeof initialized?.policy_file === "string" ? initialized.policy_file.trim() : "";
    if (!policyFile) throw new Error(t("error.noPolicyFile"));
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
        persistenceSetupError = error.message || t("error.persistSetupFailed");
      }
    }
    const [policies, keyData] = await Promise.all([
      api(PATHS.policies, { method: "GET" }),
      fetchCurrentKeys({ includeCatalog: true })
    ]);
    return { status, policies, keys: keyData.keys, catalog: keyData.catalog, persistenceSetupError };
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

  function setSessionState(kind, titleKey, messageKey, params = {}) {
    state.sessionView = { kind, titleKey, messageKey, params };
    $("#authTitle").textContent = t(titleKey);
    $("#authMessage").textContent = t(messageKey, params);
    $("#sessionIcon").classList.toggle("error", kind === "error");
    $("#sessionIcon").innerHTML = kind === "loading" ? icons.spinner : kind === "error" ? icons.warning : icons.check;
    $("#retrySessionButton").hidden = kind !== "error";
  }

  async function connectFromCPAMC() {
    if (state.sessionBusy) return;
    const token = readCPAMCManagementKey();
    if (!token) {
      state.token = "";
      setSessionState("error", "session.noSessionTitle", "session.noSessionMessage");
      return;
    }
    state.token = token;
    state.sessionBusy = true;
    setSessionState("loading", "session.connectingTitle", "session.loadingMessage");
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
      if (error.status === 401) setSessionState("error", "session.unavailableTitle", "session.expired");
      else setSessionState("error", "session.unavailableTitle", "session.connectFailed", { message: error.message });
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
    setSessionState("error", "session.endedTitle", hadDraft ? "session.endedDraft" : "session.endedNoDraft");
  }

  function setBusy(busy, action = "") {
    state.busy = busy;
    $("#workspace").inert = busy;
    refreshDataButton.disabled = busy || state.modelBusy;
    saveButton.disabled = busy || state.modelBusy || !state.dirty;
    reloadButton.disabled = busy || state.modelBusy || !state.status?.persistent_updates;
    saveButton.innerHTML = action === "save" && busy ? `${icons.spinner}<span>${escapeHTML(t("action.saving"))}</span>` : escapeHTML(t("action.save"));
    reloadButton.innerHTML = action === "reload" && busy ? icons.spinner : icons.file;
    refreshDataButton.innerHTML = action === "refresh" && busy ? icons.spinner : icons.refresh;
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
    healthBadge.innerHTML = `<span class="status-dot ${warning ? "warning" : healthy ? "" : "error"}"></span><span>${escapeHTML(warning ? t("health.warning") : healthy ? t("health.ok", { revision: state.revision }) : t("health.disconnected"))}</span>`;
    healthBadge.title = warning ? state.status.last_error : healthy ? `Schema v${state.status.schema_version || 2}` : "";
    saveButton.disabled = state.busy || state.modelBusy || !state.dirty;
    reloadButton.disabled = state.busy || state.modelBusy || !state.status?.persistent_updates;
    reloadButton.title = t(state.status?.persistent_updates ? "action.reload" : "action.reloadUnavailable");
    if (!state.busy) saveButton.textContent = t("action.save");
    saveBar.dataset.visible = String(state.dirty);
    document.documentElement.classList.toggle("has-changes", state.dirty);
  }

  function syncPersistence() {
    const notice = $("#persistenceNotice");
    if (!state.status) return;
    if (state.status.persistent_updates) {
      notice.className = "persistence-notice";
      notice.innerHTML = `<span>${escapeHTML(state.status.policy_file)}</span>`;
      notice.title = t("persist.title", { path: state.status.policy_file });
    } else {
      notice.className = "persistence-notice warning";
      notice.title = "";
      notice.textContent = state.persistenceSetupError
        ? t("persist.failed", { error: state.persistenceSetupError })
        : t("persist.memory");
    }
  }

  function scheduleNavRender() {
    if (navFrame) return;
    navFrame = requestAnimationFrame(() => {
      navFrame = 0;
      renderNav();
    });
  }

  function ruleBadge(key) {
    if (!hasRules(key)) return `<span class="rule-badge muted">${escapeHTML(t("badge.default"))}</span>`;
    const allow = key.allow_models.length ? `<span class="rule-count allow" title="${escapeHTML(t("badge.allowRules"))}">${key.allow_models.length}</span>` : "";
    const deny = key.deny_models.length ? `<span class="rule-count deny" title="${escapeHTML(t("badge.denyRules"))}">${key.deny_models.length}</span>` : "";
    return `<span class="rule-badge">${allow}${deny}</span>`;
  }

  function renderNav() {
    const query = state.search.trim().toLowerCase();
    const visible = state.keys.map((key, index) => ({ key, index })).filter(({ key, index }) =>
      !query || key.mask.toLowerCase().includes(query) || key.fingerprint.toLowerCase().includes(query) || keyLabel(index).toLowerCase().includes(query)
    );
    nav.innerHTML = `
      <button class="nav-item" type="button" data-select="overview" aria-current="${state.selectedIndex < 0 ? "page" : "false"}">
        <span class="nav-icon">${icons.overview}</span>
        <span class="nav-copy"><strong>${escapeHTML(t("nav.overview"))}</strong></span>
      </button>
      <p class="nav-group-label"><span>API Keys</span><span id="policyCount">${state.keys.length}</span></p>
      ${visible.length ? visible.map(({ key, index }) => `
        <button class="nav-item" type="button" data-select="key" data-index="${index}" aria-current="${state.selectedIndex === index ? "page" : "false"}" aria-label="${escapeHTML(keyLabel(index))}${escapeHTML(t("list.separator"))}${escapeHTML(key.mask)}" title="SHA-256 ${escapeHTML(key.fingerprint)}">
          <span class="nav-icon">${icons.key}</span>
          <span class="nav-copy"><strong>${escapeHTML(keyLabel(index))}</strong><span>${escapeHTML(key.mask)}</span></span>
          ${ruleBadge(key)}
        </button>`).join("") : `<p class="empty-nav">${escapeHTML(t(query ? "nav.noMatch" : "nav.noKeys"))}</p>`}
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
      ? `<div class="notice">${icons.warning}<p><strong>${escapeHTML(t("overview.lastErrorTitle"))}</strong>${escapeHTML(t("overview.lastError", { error: state.status.last_error }))}</p></div>`
      : "";
    const staleWarning = staleCount
      ? `<div class="notice">${icons.warning}<p><strong>${escapeHTML(t("overview.staleTitle", { count: staleCount }))}</strong>${escapeHTML(t("overview.staleBody"))}</p></div>`
      : "";
    const keyRows = state.keys.map((key, index) => `
      <button class="key-row" type="button" data-select="key" data-index="${index}">
        <span class="key-row-name"><strong>${escapeHTML(keyLabel(index))}</strong><span class="mono">${escapeHTML(key.mask)}</span></span>
        <span class="key-row-rules">${hasRules(key) ? `${rulesSummary(key.allow_models, t("rules.allow"))}${rulesSummary(key.deny_models, t("rules.deny"), true)}` : `<span class="muted">${escapeHTML(t("rules.defaultAllowAll"))}</span>`}</span>
        <span class="key-row-chevron" aria-hidden="true">${icons.chevronRight}</span>
      </button>`).join("");

    editor.innerHTML = `
      <header class="editor-head">
        <h1>${escapeHTML(t("overview.title"))}</h1>
        <p class="editor-subtitle">${escapeHTML(t("overview.subtitle"))}</p>
      </header>
      ${statusWarning}
      ${staleWarning}
      <section class="stats" aria-label="${escapeHTML(t("overview.statsLabel"))}">
        ${statCard("API Keys", state.keys.length)}
        ${statCard(t("overview.configured"), configured)}
        ${statCard(t("overview.defaultAllow"), defaults)}
        ${statCard(t("overview.stale"), staleCount, staleCount > 0)}
      </section>
      <section class="section">
        <h2 class="section-title">API Keys</h2>
        <div class="card key-list">${keyRows || `<p class="card-empty">${escapeHTML(t("nav.noKeys"))}</p>`}</div>
      </section>
      <section class="section">
        <h2 class="section-title">${escapeHTML(t("overview.status"))}</h2>
        <dl class="card status-grid">
          ${statusRow(t("overview.authMode"), displayAuthMode(state.status?.auth_mode))}
          ${statusRow(t("overview.identitySource"), state.status?.identity_source || "—")}
          ${statusRow(t("overview.unconfiguredKeys"), state.status?.unconfigured_key_action === "allow" ? t("overview.allowAll") : state.status?.unconfigured_key_action || "—")}
          ${statusRow(t("overview.policyCount"), state.status?.policy_count ?? "—")}
          ${statusRow(t("overview.revision"), `rev-${state.revision}`)}
          ${statusRow(t("overview.source"), state.status?.source || "—")}
          ${statusRow("Schema", `v${state.status?.schema_version || 2}`)}
          ${statusRow(t("overview.updatedAt"), formatDate(state.status?.updated_at))}
        </dl>
      </section>`;
  }

  function rulesSummary(models, label, deny = false) {
    if (!models.length) return "";
    const preview = models.slice(0, 2).join(", ");
    const more = models.length > 2 ? ` +${models.length - 2}` : "";
    return `<span class="rules-summary ${deny ? "deny" : "allow"}"><span class="rules-label">${escapeHTML(label)}</span><span class="mono">${escapeHTML(preview)}${more}</span></span>`;
  }

  function statCard(label, value, warning = false) {
    return `<div class="stat ${warning ? "warning" : ""}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`;
  }

  function displayAuthMode(value) {
    return value === "cpa_builtin_api_keys" ? t("overview.builtinAuth") : value || "—";
  }

  function statusRow(label, value) {
    return `<div class="status-item"><dt>${escapeHTML(label)}</dt><dd class="mono">${escapeHTML(value)}</dd></div>`;
  }

  function renderKeyEditor(key, index) {
    const empty = !hasRules(key);
    editor.innerHTML = `
      <header class="editor-head">
        <h1>${escapeHTML(keyLabel(index))}</h1>
        <p class="editor-subtitle key-summary">
          <span class="key-mask mono">${escapeHTML(key.mask)}</span>
          <span class="key-fingerprint mono" title="${escapeHTML(t("key.fingerprintTitle"))}">SHA-256 ${escapeHTML(key.fingerprint)}</span>
          <span class="pill ${empty ? "" : "active"}">${escapeHTML(t(empty ? "rules.defaultAllowAll" : "rules.configured"))}</span>
        </p>
      </header>
      <section class="card rules-card">
        ${modelPicker("allow_models", t("rules.allow"), t("rules.allowDescription"), key.allow_models, false)}
        ${modelPicker("deny_models", t("rules.deny"), t("rules.denyDescription"), key.deny_models, true)}
      </section>
      <p class="privacy-note">${escapeHTML(t("key.privacy"))}</p>`;
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
      ? t("picker.allModelsWildcard")
      : state.models.length
        ? effectiveCatalogCount ? t("picker.matched", { matched: effectiveCatalogCount, total: state.models.length }) : t("picker.chooseFrom", { total: state.models.length })
        : selectedModels.length ? t("picker.keptRules", { count: selectedModels.length }) : t("picker.catalogUnavailable");
    const wildcardLabel = escapeHTML(t("picker.wildcard"));
    const chips = selectedModels.length
      ? selectedModels.map((model) => {
          const wildcard = model.includes("*") || model.includes("?");
          const outsideCatalog = !wildcard && !state.models.some((candidate) => candidate.id === model);
          return `<span class="chip ${deny ? "deny" : ""}"><span>${escapeHTML(model)}</span>${wildcard ? `<small>${wildcardLabel}</small>` : outsideCatalog ? `<small>${escapeHTML(t("picker.outsideCatalog"))}</small>` : ""}<button class="chip-remove" type="button" data-action="remove-model" data-kind="${kind}" data-model="${escapeHTML(model)}" aria-label="${escapeHTML(t("picker.removeRule"))}">${icons.close}</button></span>`;
        }).join("")
      : `<span class="empty-chips">${escapeHTML(t(deny ? "picker.noDenied" : "picker.unrestricted"))}</span>`;
    const wildcardRow = `<button class="model-option wildcard-option ${wildcardSelected ? "selected" : ""}" type="button" role="option" aria-selected="${wildcardSelected}" data-action="toggle-model" data-kind="${kind}" data-model="*" data-search="全部模型 all models wildcard *">
      <span class="model-checkbox" aria-hidden="true">${wildcardSelected ? icons.check : ""}</span>
      <span class="model-option-copy"><strong>${escapeHTML(t("picker.allModels"))}</strong><small>${escapeHTML(t(deny ? "picker.allDenyHint" : "picker.allAllowHint"))}</small></span>
      <span class="model-badge">${wildcardLabel}</span>
    </button>`;
    const commonWildcards = ["gpt-*", "claude-*", "gemini-*", "qwen-*", "deepseek-*", "grok-*", "kimi-*", "glm-*", "minimax-*"];
    const presetRows = commonWildcards.filter((rule) => selected.has(rule) || state.models.some((model) => modelPatternMatches(rule, model.id))).map((rule) => {
      const explicit = selected.has(rule);
      const derived = wildcardSelected && !explicit;
      const checked = explicit || derived;
      const matchCount = state.models.filter((model) => modelPatternMatches(rule, model.id)).length;
      return `<button class="model-option preset-option ${checked ? "selected" : ""} ${derived ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" aria-disabled="${derived}" data-action="toggle-model" data-kind="${kind}" data-model="${rule}" data-locked="${derived}" data-search="${rule} 通配符 wildcard">
        <span class="model-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span>
        <span class="model-option-copy"><strong>${rule}</strong><small>${escapeHTML(t("picker.presetHint", { count: matchCount }))}</small></span>
        <span class="model-badge">${wildcardLabel}</span>
      </button>`;
    }).join("");
    const rows = state.models.map((model) => {
      const explicit = selected.has(model.id);
      const matchedRule = explicit ? "" : matchedRuleFor(model.id);
      const derived = Boolean(matchedRule);
      const checked = explicit || derived;
      return `<button class="model-option ${checked ? "selected" : ""} ${derived ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" aria-disabled="${derived}" data-action="toggle-model" data-kind="${kind}" data-model="${escapeHTML(model.id)}" data-locked="${derived}" data-search="${escapeHTML(`${model.id} ${model.displayName}`.toLowerCase())}">
        <span class="model-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span>
        <span class="model-option-copy"><strong>${escapeHTML(model.id)}</strong>${model.displayName ? `<small>${escapeHTML(model.displayName)}</small>` : ""}${derived ? `<small>${escapeHTML(t("picker.matchedBy", { rule: matchedRule }))}</small>` : ""}</span>
        ${derived ? `<span class="model-badge">${wildcardLabel}</span>` : ""}
      </button>`;
    }).join("");

    return `<div class="model-editor ${deny ? "deny" : ""}">
      <div class="tag-head"><div><strong><span class="kind-dot" aria-hidden="true"></span>${escapeHTML(title)}</strong><span>${escapeHTML(description)}</span></div><span class="selection-count">${escapeHTML(t("rules.count", { count: selectedModels.length }))}</span></div>
      <div class="chips">${chips}</div>
      <button class="model-trigger ${isOpen ? "open" : ""}" type="button" data-action="toggle-picker" data-kind="${kind}" aria-expanded="${isOpen}">
        <span>${escapeHTML(summary)}</span><span class="picker-chevron" aria-hidden="true">${icons.chevronDown}</span>
        ${state.models.length ? `<progress class="selection-meter" max="${state.models.length}" value="${effectiveCatalogCount}" aria-label="${escapeHTML(t("picker.matched", { matched: effectiveCatalogCount, total: state.models.length }))}"></progress>` : ""}
      </button>
      ${isOpen ? `<div class="model-panel ${state.pickerAnimate === kind ? "animate-in" : ""}">
        ${state.models.length ? `<div class="model-search"><span>${icons.search}</span><input type="search" data-model-search="${kind}" value="${escapeHTML(state.pickerQuery)}" autocomplete="off" placeholder="${escapeHTML(t("picker.searchPlaceholder"))}" aria-label="${escapeHTML(t("picker.searchLabel", { title }))}"></div>
        <div class="model-list" role="listbox" aria-multiselectable="true">${wildcardRow}${presetRows}${rows}<p class="model-empty" hidden>${escapeHTML(t("picker.noMatch"))}</p></div>
        <div class="model-panel-footer"><span>${escapeHTML(t("picker.footerMatched", { matched: effectiveCatalogCount, total: state.models.length }))}</span><div><button type="button" data-action="select-all-models" data-kind="${kind}">${escapeHTML(t("picker.selectAll"))}</button><button type="button" data-action="clear-models" data-kind="${kind}">${escapeHTML(t("picker.clear"))}</button></div></div>`
        : `<div class="model-list compact" role="listbox" aria-multiselectable="true">${wildcardRow}</div><div class="catalog-notice"><span>${escapeHTML(state.modelsError || t("picker.noCatalog"))}</span><button type="button" data-action="refresh-models">${escapeHTML(t("picker.reload"))}</button></div>`}
      </div>` : ""}
    </div>`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(date);
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
    scheduleNavRender();
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
    if (retryButton) { retryButton.disabled = true; retryButton.innerHTML = `${icons.spinner}<span>${escapeHTML(t("picker.loading"))}</span>`; }
    try {
      const result = await fetchCurrentKeys({ includeCatalog: true });
      state.models = result.catalog?.models || [];
      state.modelsError = result.catalog?.error || "";
      renderEditor();
      showToast(state.models.length ? t("picker.loaded", { count: state.models.length }) : state.modelsError, state.models.length ? "success" : "error");
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
        const changed = new Error(t("save.keySetChanged"));
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
        showToast(t("save.keysChangedAfter"), "error");
      } else if (postSaveCheckError) {
        showToast(t("save.verifyFailed", { message: postSaveCheckError.message }), "error");
      } else {
        showToast(t(response?.persistent ? "save.persisted" : "save.memory"), "success");
      }
      try {
        state.status = await api(PATHS.status, { method: "GET" });
        syncHeader();
        syncPersistence();
      } catch (refreshError) {
        showToast(t("save.statusFailed", { message: refreshError.message }), "error");
      }
    } catch (error) {
      if (error.code === "timeout") {
        const confirmed = await confirmTimedOutSave(submittedPolicy, expectedRevision);
        showToast(t(confirmed ? "save.timeoutConfirmed" : "save.timeoutUnconfirmed"), confirmed ? "success" : "error");
      } else if (error.code === "key_set_changed") {
        showToast(error.message, "error", t("action.refreshData"), refreshData);
      } else if (error.status === 412) {
        showToast(t("save.conflict"), "error", t("action.refreshData"), refreshData);
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
    if (state.dirty && !window.confirm(t("refresh.confirm"))) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "refresh");
    try {
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast(t("refresh.done"), "success");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function reload() {
    if (state.busy || !state.status?.persistent_updates) return;
    if (state.dirty && !window.confirm(t("reload.confirm"))) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "reload");
    let reloaded = false;
    try {
      await api(PATHS.reload, { method: "POST" });
      reloaded = true;
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast(t("reload.done"), "success");
    } catch (error) {
      showToast(reloaded ? t("reload.uiFailed", { message: error.message }) : error.message, "error");
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

  function syncLocale() {
    const next = detectLocale();
    if (next === locale) return;
    locale = next;
    applyStaticTranslations();
    if (state.sessionView) {
      const { kind, titleKey, messageKey, params } = state.sessionView;
      setSessionState(kind, titleKey, messageKey, params);
    }
    if (!app.hidden) renderAll();
    if (!state.busy) setBusy(false);
    if (state.openPicker) restorePickerView(state.openPicker);
  }

  function initializeChrome() {
    applyStaticTranslations();
    document.documentElement.classList.toggle("is-embedded", window.self !== window.top);
    $("#searchIcon").innerHTML = icons.search;
    refreshDataButton.innerHTML = icons.refresh;
    reloadButton.innerHTML = icons.file;
    const shortcut = saveBar.querySelector(".shortcut");
    if (shortcut && !/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)) shortcut.textContent = "Ctrl S";
    syncTheme();
    try {
      if (window.self !== window.top) {
        new MutationObserver(syncTheme).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
        new MutationObserver(syncLocale).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["lang"] });
      }
    } catch (_) { /* cross-origin embedding is unsupported for session reuse */ }
  }

  $("#retrySessionButton").addEventListener("click", connectFromCPAMC);
  window.addEventListener("storage", (event) => {
    if (event.key === CPAMC_THEME_KEY) syncTheme();
    if (event.key === CPAMC_LANGUAGE_KEY || event.key === "i18nextLng") syncLocale();
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

  function selectView(item) {
    const nextIndex = item.dataset.select === "overview" ? -1 : Number(item.dataset.index);
    const changed = nextIndex !== state.selectedIndex;
    state.selectedIndex = nextIndex;
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    renderNav();
    renderEditor();
    if (changed) window.scrollTo({ top: 0 });
  }

  nav.addEventListener("click", (event) => {
    if (state.busy) return;
    const item = event.target.closest("[data-select]");
    if (item) selectView(item);
  });

  editor.addEventListener("click", (event) => {
    if (state.busy) return;
    const target = event.target.closest("button");
    if (!target) return;
    if (target.dataset.select) { selectView(target); return; }
    const action = target.dataset.action;
    const kind = target.dataset.kind;
    if (action === "toggle-picker" && validModelKind(kind)) {
      const opening = state.openPicker !== kind;
      state.openPicker = opening ? kind : "";
      if (opening) { state.pickerQuery = ""; state.pickerScroll = 0; }
      // Animate only the moment a picker opens; re-renders while toggling models stay still.
      state.pickerAnimate = opening ? kind : "";
      renderEditor();
      state.pickerAnimate = "";
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
    if (event.key === "Escape" && state.openPicker && !state.busy) {
      const kind = state.openPicker;
      state.openPicker = "";
      renderEditor();
      editor.querySelector(`[data-action="toggle-picker"][data-kind="${kind}"]`)?.focus();
      return;
    }
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
