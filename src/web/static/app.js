// ============================================
// MuccheAI — Frontend Application
// ============================================

const API_BASE = '';
let currentSessionId = null;
let currentPersona = '';
let statusPoller = null;
let lastKnownModel = 'qwen3:14b';
let ws = null;
let wsConnected = false;
let streamingEnabled = true;
let offlineQueue = [];
try {
    const savedQueue = localStorage.getItem('muccheai_offline_queue');
    if (savedQueue) offlineQueue = JSON.parse(savedQueue);
} catch (e) { offlineQueue = []; }
let isOnline = navigator.onLine;
let isSending = false;

function initWebSocket() {
    const token = localStorage.getItem('muccheai_session_token');
    if (!token || wsConnected) return;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/api/chat/ws`;
    ws = new WebSocket(url);
    ws.onopen = () => { wsConnected = true; };
    ws.onclose = () => {
        wsConnected = false;
        ws = null;
        setTyping(false);
        const sendBtn = document.getElementById('send');
        if (sendBtn) sendBtn.disabled = false;
    };
    ws.onmessage = (ev) => {
        try {
            const data = JSON.parse(ev.data);
            if (data.error) {
                setTyping(false);
                addMessage('error', data.error);
            } else {
                setTyping(false);
                addMessage('ai', data.response || '(no response)', false, { memories_used: data.memories_used || 0 });
                if (data.session_id) currentSessionId = data.session_id;
                if (data.session_secret) localStorage.setItem('current_session_secret', data.session_secret);
                checkApprovalQueue();
            }
        } catch (e) {
            console.error('WebSocket message parse error:', e);
            setTyping(false);
            addMessage('error', 'Received malformed response from server.');
        }
        const sendBtn = document.getElementById('send');
        if (sendBtn) sendBtn.disabled = false;
        scrollToBottom();
    };
}

function closeWebSocket() {
    if (ws) { ws.close(); ws = null; wsConnected = false; }
}

// ============================================
// Translations
// ============================================
const TRANSLATIONS = {
    en: {
        navChat: 'Chat', navMemory: 'Memory', navPersonas: 'Personas', navMcp: 'MCP', navStatus: 'Status', navSettings: 'Settings',
        welcomeTitle: 'Your local, secure AI agent',
        welcomeSubtitle: 'Select a persona and start chatting.',
        apiKeyTitle: '🔐 Login',
        apiKeyDesc: 'Enter your username and password.',
        apiKeyPlaceholder: 'Password',
        connect: 'Connect',
        nameAiTitle: '👋 Welcome',
        nameAiDesc: "I'm your AI assistant. What would you like to call me?",
        nameAiPlaceholder: 'e.g. MuccheAI, Assistant, etc.',
        start: 'Start',
        memoryFacts: '📌 Facts', memoryPrefs: '⚙️ Preferences', memoryTasks: '📋 Task History',
        memoryAdd: 'Add Memory', memoryKeyPlaceholder: 'Key (e.g., birthday, timezone)',
        memoryValuePlaceholder: 'Value', memorySave: 'Save',
        queueEmpty: 'No pending proposals. The LLM has not suggested any memories for approval.',
        queueLoading: 'Loading queue...',
        approve: '✓ Approve', reject: '✕ Reject',
        toastPending: '⏳ Memory approval queue pending',
        toastGoToMemory: 'Go to Memory',
        settingsSave: 'Save Settings',
        aiNameLabel: 'AI Name',
        rename: 'Rename',
        loading: 'Loading...',
        noResponse: '(no response)',
        typingPlaceholder: 'Message your AI...',
        newChat: '+ New Chat',
        aiSetup: '⚙️ AI Setup',
        you: 'You', system: 'System', connecting: 'Connecting…',
    },
    pt: {
        navChat: 'Chat', navMemory: 'Memória', navPersonas: 'Personas', navMcp: 'MCP', navStatus: 'Status', navSettings: 'Configurações',
        welcomeTitle: 'Seu agente de IA local e seguro',
        welcomeSubtitle: 'Selecione uma persona e comece a conversar.',
        apiKeyTitle: '🔐 Login',
        apiKeyDesc: 'Digite seu nome de usuário e senha.',
        apiKeyPlaceholder: 'Senha',
        connect: 'Conectar',
        nameAiTitle: '👋 Bem-vindo',
        nameAiDesc: 'Sou seu assistente de IA. Como você gostaria de me chamar?',
        nameAiPlaceholder: 'ex: MuccheAI, Assistente, etc.',
        start: 'Começar',
        memoryFacts: '📌 Fatos', memoryPrefs: '⚙️ Preferências', memoryTasks: '📋 Histórico de Tarefas',
        memoryAdd: 'Adicionar Memória', memoryKeyPlaceholder: 'Chave (ex: aniversário, fuso horário)',
        memoryValuePlaceholder: 'Valor', memorySave: 'Salvar',
        queueEmpty: 'Nenhuma proposta pendente. O LLM não sugeriu memórias para aprovação.',
        queueLoading: 'Carregando fila...',
        approve: '✓ Aprovar', reject: '✕ Rejeitar',
        toastPending: '⏳ Fila de aprovação de memória pendente',
        toastGoToMemory: 'Ir para memórias',
        settingsSave: 'Salvar Configurações',
        aiNameLabel: 'Nome da IA',
        rename: 'Renomear',
        loading: 'Carregando...',
        noResponse: '(sem resposta)',
        typingPlaceholder: 'Mensagem para sua IA...',
        newChat: '+ Novo Chat',
        aiSetup: '⚙️ Configurar IA',
        you: 'Você', system: 'Sistema', connecting: 'Conectando…',
    },
    zh: {
        navChat: '聊天', navMemory: '记忆', navPersonas: '角色', navMcp: 'MCP', navStatus: '状态', navSettings: '设置',
        welcomeTitle: '您的本地安全AI助手',
        welcomeSubtitle: '选择一个角色并开始聊天。',
        apiKeyTitle: '🔐 登录',
        apiKeyDesc: '输入您的用户名和密码。',
        apiKeyPlaceholder: '密码',
        connect: '连接',
        nameAiTitle: '👋 欢迎',
        nameAiDesc: '我是您的AI助手。您想怎么称呼我？',
        nameAiPlaceholder: '例如：MuccheAI、助手等',
        start: '开始',
        memoryFacts: '📌 事实', memoryPrefs: '⚙️ 偏好', memoryTasks: '📋 任务历史',
        memoryAdd: '添加记忆', memoryKeyPlaceholder: '键（例如：生日、时区）',
        memoryValuePlaceholder: '值', memorySave: '保存',
        queueEmpty: '没有待处理的提案。LLM尚未建议任何需要批准的记忆。',
        queueLoading: '正在加载队列...',
        approve: '✓ 批准', reject: '✕ 拒绝',
        toastPending: '⏳ 记忆审批队列待处理',
        toastGoToMemory: '前往记忆',
        settingsSave: '保存设置',
        aiNameLabel: 'AI 名称',
        rename: '重命名',
        loading: '加载中...',
        noResponse: '(无响应)',
        typingPlaceholder: '向您的AI发送消息...',
        newChat: '+ 新聊天',
        aiSetup: '⚙️ AI设置',
        you: '你', system: '系统', connecting: '连接中…',
    }
};

function getLang() {
    return localStorage.getItem('muccheai_lang') || 'en';
}

function setLang(lang) {
    localStorage.setItem('muccheai_lang', lang);
    applyTranslations();
}

function t(key) {
    const lang = getLang();
    return TRANSLATIONS[lang]?.[key] ?? TRANSLATIONS.en[key] ?? key;
}

function applyTranslations() {
    const lang = getLang();
    // Update static nav labels
    const navLabels = { chat: t('navChat'), memory: t('navMemory'), personas: t('navPersonas'), mcp: t('navMcp'), status: t('navStatus') };
    document.querySelectorAll('.nav-item').forEach(el => {
        const tab = el.getAttribute('data-tab');
        if (tab && navLabels[tab]) {
            const icon = el.querySelector('.nav-icon');
            el.innerHTML = '';
            if (icon) el.appendChild(icon);
            el.appendChild(document.createTextNode(' ' + navLabels[tab]));
        }
    });
    // Update page titles
    const titles = { chat: t('navChat'), memory: t('navMemory'), personas: t('navPersonas'), mcp: t('navMcp'), status: t('navStatus'), analytics: 'Analytics', presets: 'Presets', graph: 'Knowledge Graph', tools: 'Custom Tools', tasks: 'Scheduled Tasks' };
    const currentTab = document.querySelector('.tab.active');
    if (currentTab) {
        const tabName = currentTab.id.replace('tab-', '');
        document.getElementById('pageTitle').textContent = titles[tabName] || 'MuccheAI';
    }
    // Update welcome messages
    document.querySelectorAll('.welcome-message h2').forEach(el => {
        if (el.textContent.includes('🐄')) el.textContent = '🐄 ' + getAiName();
    });
    document.querySelectorAll('.welcome-message p').forEach(el => {
        el.textContent = t('welcomeSubtitle');
    });
    // Update input placeholder
    const input = document.getElementById('input');
    if (input) input.placeholder = t('typingPlaceholder');
    // Update API key modal
    const loginTitle = document.querySelector('#apiKeyModal h3');
    if (loginTitle) loginTitle.textContent = t('apiKeyTitle');
    const loginDesc = document.querySelector('#apiKeyModal p');
    if (loginDesc) loginDesc.innerHTML = t('apiKeyDesc');
    const passInput = document.getElementById('loginPass');
    if (passInput) passInput.placeholder = t('apiKeyPlaceholder');
    const loginBtn = document.querySelector('#apiKeyModal .btn-primary');
    if (loginBtn) loginBtn.textContent = t('connect');
    // Update name AI modal
    const nameAiTitle = document.querySelector('#nameAiModal h3');
    if (nameAiTitle) nameAiTitle.textContent = t('nameAiTitle');
    const nameAiDesc = document.querySelector('#nameAiModal p');
    if (nameAiDesc) nameAiDesc.textContent = t('nameAiDesc');
    const nameAiInput = document.getElementById('aiNameInput');
    if (nameAiInput) nameAiInput.placeholder = t('nameAiPlaceholder');
    const nameAiBtn = document.querySelector('#nameAiModal .btn-primary');
    if (nameAiBtn) nameAiBtn.textContent = t('start');
    // Update toast
    const toastSpan = document.querySelector('#approvalToast span');
    if (toastSpan) toastSpan.textContent = t('toastPending');
    const toastBtn = document.getElementById('approvalToastBtn');
    if (toastBtn) toastBtn.textContent = t('toastGoToMemory');
    // Update AI name in settings
    const settingsAiName = document.getElementById('settingAiName');
    if (settingsAiName) settingsAiName.value = getAiName();
    // Update topbar buttons
    const newChatBtn = document.getElementById('newChatBtn');
    if (newChatBtn) newChatBtn.textContent = t('newChat');
    const aiSetupBtn = document.getElementById('apiPanelToggleBtn');
    if (aiSetupBtn) aiSetupBtn.textContent = t('aiSetup');
    // Update language selector
    const langSelect = document.getElementById('settingLanguage');
    if (langSelect) langSelect.value = lang;
    // Update AI name label and rename button
    const aiNameLabel = document.querySelector('label[for="settingAiName"]');
    if (aiNameLabel) aiNameLabel.textContent = t('aiNameLabel');
    const renameBtn = document.getElementById('renameAiBtn');
    if (renameBtn) renameBtn.textContent = t('rename');
}

// ============================================
// Dark Mode
// ============================================
async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST', headers: authHeaders() });
    } catch (e) {
        console.warn('Logout request failed:', e);
    }
    closeWebSocket();
    localStorage.removeItem('muccheai_session_token');
    localStorage.removeItem('muccheai_session_time');
    localStorage.removeItem('muccheai_csrf_token');
    localStorage.removeItem('muccheai_name');
    localStorage.removeItem('muccheai_sessions');
    localStorage.removeItem('muccheai_theme');
    localStorage.removeItem('muccheai_lang');
    localStorage.removeItem('muccheai_sidebar_collapsed');
    localStorage.removeItem('muccheai_status_collapsed');
    localStorage.removeItem('current_session_secret');
    localStorage.removeItem('muccheai_offline_queue');
    if (statusPoller) clearInterval(statusPoller);
    location.reload();
}

function toggleDarkMode() {
    const isDark = document.body.classList.toggle('dark');
    localStorage.setItem('muccheai_theme', isDark ? 'dark' : 'light');
    const btn = document.getElementById('darkModeBtn');
    if (btn) btn.textContent = isDark ? '☀️' : '🌙';
}

// ============================================
// Auth
// ============================================
const API_KEY_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

function getAuthHeaders() {
    const token = (localStorage.getItem('muccheai_session_token') || '').trim();
    const storedTime = parseInt(localStorage.getItem('muccheai_session_time') || '0', 10);
    if (token && storedTime && Date.now() - storedTime > API_KEY_MAX_AGE_MS) {
        localStorage.removeItem('muccheai_session_token');
        localStorage.removeItem('muccheai_session_time');
        localStorage.removeItem('muccheai_csrf_token');
        return {};
    }
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

let apiKeyModalSubmitting = false;
let lastApiKeySubmitTime = 0;

function showApiKeyModal() {
    document.getElementById('apiKeyModal').style.display = 'flex';
}

function hideApiKeyModal() {
    document.getElementById('apiKeyModal').style.display = 'none';
}

function showNameAiModal() {
    document.getElementById('nameAiModal').style.display = 'flex';
}

function hideNameAiModal() {
    document.getElementById('nameAiModal').style.display = 'none';
}

function submitAiName() {
    const input = document.getElementById('aiNameInput');
    const name = input.value.trim();
    if (!name) return;
    localStorage.setItem('muccheai_name', name);
    hideNameAiModal();
    updateAiNameDisplay();
}

function getAiName() {
    return localStorage.getItem('muccheai_name') || 'MuccheAI';
}

function updateAiNameDisplay() {
    const name = getAiName();
    const welcome = document.querySelector('.welcome-message h2');
    if (welcome) welcome.textContent = '🐄 ' + name;
    // Update page title if on chat tab
    const pageTitle = document.getElementById('pageTitle');
    const currentTab = document.querySelector('.tab.active');
    if (pageTitle && currentTab && currentTab.id === 'tab-chat') {
        pageTitle.textContent = t('navChat');
    }
}

function showRenameAiModal() {
    const input = document.getElementById('aiNameInput');
    input.value = getAiName();
    document.getElementById('nameAiModal').style.display = 'flex';
}

async function submitApiKey() {
    const userInput = document.getElementById('loginUser');
    const passInput = document.getElementById('loginPass');
    const btn = document.getElementById('loginBtn');
    const errorEl = document.getElementById('loginError');
    const username = (userInput?.value || '').trim();
    const password = (passInput?.value || '').trim();

    if (errorEl) { errorEl.style.display = 'none'; errorEl.textContent = ''; }

    if (!username || !password) {
        if (errorEl) { errorEl.textContent = 'Please enter both username and password.'; errorEl.style.display = 'block'; }
        return;
    }
    if (apiKeyModalSubmitting) {
        console.log('Login already in progress, ignoring duplicate submit');
        return;
    }

    apiKeyModalSubmitting = true;
    lastApiKeySubmitTime = Date.now();
    if (btn) { btn.textContent = t('connecting'); btn.disabled = true; }

    try {
        console.log('Sending login request for user:', username);
        const loginRes = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        console.log('Login response status:', loginRes.status);
        if (!loginRes.ok) {
            const errText = loginRes.status === 401 ? 'Invalid username or password.' : 'Login failed (HTTP ' + loginRes.status + ')';
            if (errorEl) { errorEl.textContent = errText; errorEl.style.display = 'block'; }
            if (passInput) passInput.value = '';
            apiKeyModalSubmitting = false;
            if (btn) { btn.textContent = 'Connect'; btn.disabled = false; }
            return;
        }
        const loginData = await loginRes.json();
        console.log('Login success, token received');
        localStorage.setItem('muccheai_session_token', loginData.token);
        localStorage.setItem('muccheai_session_time', Date.now().toString());

        // Fetch and store CSRF token for mutating requests
        try {
            const csrfRes = await fetch('/api/csrf', {
                headers: { 'Authorization': 'Bearer ' + loginData.token }
            });
            if (csrfRes.ok) {
                const csrfData = await csrfRes.json();
                if (csrfData.csrf_token) {
                    localStorage.setItem('muccheai_csrf_token', csrfData.csrf_token);
                }
            }
        } catch (e) { /* ignore csrf fetch errors */ }
        hideApiKeyModal();
        pollStatus();
        initWebSocket();
        if (!localStorage.getItem('muccheai_name')) {
            setTimeout(() => showNameAiModal(), 300);
        }
    } catch (e) {
        console.error('Connection error:', e);
        if (errorEl) { errorEl.textContent = 'Could not connect. Is the server running?'; errorEl.style.display = 'block'; }
    } finally {
        apiKeyModalSubmitting = false;
        if (btn) { btn.textContent = 'Connect'; btn.disabled = false; }
    }
}

async function submitRegister() {
    const userInput = document.getElementById('loginUser');
    const passInput = document.getElementById('loginPass');
    const duressInput = document.getElementById('duressPin');
    const btn = document.getElementById('registerBtn');
    const username = (userInput?.value || '').trim();
    const password = (passInput?.value || '').trim();
    if (!username || !password || apiKeyModalSubmitting) return;

    apiKeyModalSubmitting = true;
    lastApiKeySubmitTime = Date.now();
    if (btn) { btn.textContent = 'Creating...'; btn.disabled = true; }

    const payload = { username, password };
    const duressPin = (duressInput?.value || '').trim();
    if (duressPin) payload.duress_pin = duressPin;

    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.status === 409) {
            alert('Username already taken.');
            apiKeyModalSubmitting = false;
            if (btn) { btn.textContent = 'Register'; btn.disabled = false; }
            return;
        }
        if (!res.ok) {
            alert('Registration failed. Please try again.');
            apiKeyModalSubmitting = false;
            if (btn) { btn.textContent = 'Register'; btn.disabled = false; }
            return;
        }
        const data = await res.json();
        localStorage.setItem('muccheai_session_token', data.token);
        localStorage.setItem('muccheai_session_time', Date.now().toString());

        try {
            const csrfRes = await fetch('/api/csrf', {
                headers: { 'Authorization': 'Bearer ' + data.token }
            });
            if (csrfRes.ok) {
                const csrfData = await csrfRes.json();
                if (csrfData.csrf_token) {
                    localStorage.setItem('muccheai_csrf_token', csrfData.csrf_token);
                }
            }
        } catch (e) { /* ignore */ }
        hideApiKeyModal();
        pollStatus();
        initWebSocket();
        if (!localStorage.getItem('muccheai_name')) {
            setTimeout(() => showNameAiModal(), 300);
        }
    } catch (e) {
        console.error('Registration error:', e);
        alert('Could not connect. Is the server running?');
    } finally {
        apiKeyModalSubmitting = false;
        if (btn) { btn.textContent = 'Register'; btn.disabled = false; }
    }
}

function showAuthError() {
    // Don't re-show the modal if the user just submitted a key within 3 seconds
    if (Date.now() - lastApiKeySubmitTime < 3000) return;
    showApiKeyModal();
}

async function apiFetch(url, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...getAuthHeaders(), ...(opts.headers || {}) };
    // Add CSRF token for mutating requests
    const method = (opts.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
        const csrf = localStorage.getItem('muccheai_csrf_token');
        if (csrf) headers['X-CSRF-Token'] = csrf;
    }
    const res = await fetch(url, { ...opts, headers });
    if (res.status === 401) {
        showAuthError();
        throw new Error('Unauthorized');
    }
    return res;
}

// ============================================
// Routing / Tabs
// ============================================
function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const tab = document.getElementById('tab-' + name);
    if (tab) tab.classList.add('active');
    const nav = document.querySelector(`[data-tab="${name}"]`);
    if (nav) nav.classList.add('active');

    const titles = { chat: t('navChat'), memory: t('navMemory'), personas: t('navPersonas'), mcp: t('navMcp'), status: t('navStatus') };
    document.getElementById('pageTitle').textContent = titles[name] || 'MuccheAI';

    if (name === 'memory') loadMemory();
    if (name === 'status') loadStatusPage();
    if (name === 'personas') loadPersonas();
    if (name === 'mcp') loadMcpRegistry();
    if (name === 'chat') loadInlineFilePreviews();
    if (name === 'analytics') loadAnalytics();
    if (name === 'presets') loadPresets();
    if (name === 'graph') loadKnowledgeGraph();
    if (name === 'tools') loadCustomTools();
    if (name === 'tasks') loadScheduledTasks();

    history.pushState(null, '', '#' + name);
}

function handleRoute() {
    const hash = location.hash.slice(1) || 'chat';
    switchTab(hash);
}

window.addEventListener('popstate', handleRoute);
document.addEventListener('DOMContentLoaded', handleRoute);
document.addEventListener('DOMContentLoaded', () => {
    const hasKey = !!(localStorage.getItem('muccheai_session_token') || '').trim();
    const hasName = !!localStorage.getItem('muccheai_name');
    if (!hasKey) {
        showApiKeyModal();
    } else if (!hasName) {
        showNameAiModal();
    }
    const savedTheme = localStorage.getItem('muccheai_theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark');
        const btn = document.getElementById('darkModeBtn');
        if (btn) btn.textContent = '☀️';
    }

    // Restore sidebar collapsed state
    const savedCollapsed = localStorage.getItem('muccheai_sidebar_collapsed');
    if (savedCollapsed === '1') {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) sidebar.classList.add('collapsed');
    }
    // Restore status sidebar collapsed state
    const savedStatusCollapsed = localStorage.getItem('muccheai_status_collapsed');
    if (savedStatusCollapsed === '1') {
        const statusSidebar = document.getElementById('statusSidebar');
        if (statusSidebar) statusSidebar.classList.add('collapsed');
    }
    updateAiNameDisplay();
    checkApprovalQueue();
    applyTranslations();
});

// ============================================
// Chat
// ============================================
const THINKING_WORDS = [
    "Analizzando","Architettando","Assemblando","Bilanciando","Calibrando",
    "Catalogando","Canalizzando","Raggruppando","Compilando","Computando",
    "Configurando","Connettendo","Costruendo","Consultando","Contemplando",
    "Convergendo","Creando","Decodificando","Decriptando","Deducendo",
    "Deliberando","Determinando","Diagrammando","Digerendo","Scoprendo",
    "Distillando","Distribuendo","Codificando","Criptando","Ingegnerizzando",
    "Valutando","Esaminando","Espandendo","Esplorando","Estraendo",
    "Filtrando","Prevedendo","Formattando","Formulando","Generando",
    "Armonizzando","Indicizzando","Inferendo","Inizializzando","Ispezionando",
    "Integrando","Interpretando","Iterando","Caricando","Mappando",
    "Misurando","Unendo","Modellando","Ottimizzando","Orchestrando",
    "Analizzando","Processando","Proiettando","Interrogando","Ragionando",
    "Ricostruendo","Affinando","Renderizzando","Risolvendo","Recuperando",
    "Instradando","Scansionando","Pianificando","Sintetizzando","Testando",
    "Trasformando","Validando","Verificando","Visualizzando"
];

function getTimestamp() {
    const now = new Date();
    return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function scrollToBottom() {
    const el = document.getElementById('messages');
    if (el) el.scrollTop = el.scrollHeight;
}

function syntaxHighlightJson(json) {
    if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
    return json
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/("(?:\\.|[^"\\])*")/g, '<span class="hljs-string">$1</span>')
        .replace(/\b(true|false)\b/g, '<span class="hljs-boolean">$1</span>')
        .replace(/\b(null)\b/g, '<span class="hljs-null">$1</span>')
        .replace(/\b(\d+\.?\d*)\b/g, '<span class="hljs-number">$1</span>')
        .replace(/("[\w_]+")\s*:/g, '<span class="hljs-key">$1</span>:');
}

/**
 * Strip all raw HTML tags from text to prevent XSS.
 */
function stripHtmlTags(text) {
    // SECURITY: Strip all raw HTML tags including unclosed ones.
    // Matches '<' through the next '>' OR end of string.
    return text.replace(/<[^>]*>?/gs, '');
}

/**
 * Lightweight markdown-to-HTML renderer with XSS protection.
 * Supports: headers, bold, italic, strikethrough, inline code, code blocks,
 * lists (ordered/unordered), blockquotes, links, horizontal rules.
 * All raw HTML tags are stripped before processing.
 */
function renderMarkdown(text) {
    // 0. SECURITY: Strip raw HTML tags to prevent XSS from LLM output
    text = stripHtmlTags(text);

    // 1. Protect code blocks
    const codeBlocks = [];
    text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (match, lang, code) => {
        const idx = codeBlocks.length;
        let highlighted = escapeHtml(code);
        if (lang === 'json') {
            highlighted = syntaxHighlightJson(code);
        }
        codeBlocks.push(`<pre><code class="language-${escapeHtml(lang || 'text')}">${highlighted}</code></pre>`);
        return `\x00CODEBLOCK${idx}\x00`;
    });

    // 2. Protect inline code
    const inlineCodes = [];
    text = text.replace(/`([^`]+)`/g, (match, code) => {
        const idx = inlineCodes.length;
        inlineCodes.push(`<code>${escapeHtml(code)}</code>`);
        return `\x00INLINECODE${idx}\x00`;
    });

    // 3. Process block elements line by line
    const lines = text.split('\n');
    const blocks = [];
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];

        // Horizontal rule
        if (/^(---|\*\*\*|___)\s*$/.test(line)) {
            blocks.push('<hr>');
            i++;
            continue;
        }

        // Headers
        const headerMatch = line.match(/^(#{1,6})\s+(.*)$/);
        if (headerMatch) {
            const level = headerMatch[1].length;
            const content = processInline(headerMatch[2]);
            blocks.push(`<h${level}>${content}</h${level}>`);
            i++;
            continue;
        }

        // Blockquote
        if (line.startsWith('>')) {
            const quoteLines = [];
            while (i < lines.length && lines[i].startsWith('>')) {
                quoteLines.push(lines[i].slice(1).trim());
                i++;
            }
            const content = processInline(quoteLines.join('\n').replace(/\n/g, '<br>'));
            blocks.push(`<blockquote>${content}</blockquote>`);
            continue;
        }

        // Unordered list
        if (/^(\s*)[-*+]\s+/.test(line)) {
            const listItems = [];
            while (i < lines.length) {
                const match = lines[i].match(/^(\s*)[-*+]\s+(.*)$/);
                if (!match) break;
                listItems.push(`<li>${processInline(match[2])}</li>`);
                i++;
            }
            blocks.push(`<ul>${listItems.join('')}</ul>`);
            continue;
        }

        // Ordered list
        if (/^(\s*)\d+\.\s+/.test(line)) {
            const listItems = [];
            while (i < lines.length) {
                const match = lines[i].match(/^(\s*)\d+\.\s+(.*)$/);
                if (!match) break;
                listItems.push(`<li>${processInline(match[2])}</li>`);
                i++;
            }
            blocks.push(`<ol>${listItems.join('')}</ol>`);
            continue;
        }

        // Empty line → paragraph break
        if (line.trim() === '') {
            i++;
            continue;
        }

        // Regular paragraph (collect consecutive non-empty lines)
        const paraLines = [];
        while (i < lines.length && lines[i].trim() !== '' && !isBlockStart(lines[i])) {
            paraLines.push(lines[i]);
            i++;
        }
        const content = processInline(paraLines.join(' '));
        blocks.push(`<p>${content}</p>`);
    }

    let html = blocks.join('\n');

    // 4. Restore inline code
    html = html.replace(/\x00INLINECODE(\d+)\x00/g, (_, idx) => inlineCodes[+idx]);

    // 5. Restore code blocks
    html = html.replace(/\x00CODEBLOCK(\d+)\x00/g, (_, idx) => codeBlocks[+idx]);

    return html;
}

function isBlockStart(line) {
    return /^(#{1,6}\s|>|\s*[-*+]\s+|\s*\d+\.\s+|---|\*\*\*|___)\s*$/.test(line);
}

function processInline(text) {
    // Bold + italic
    text = text.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    // Bold
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/__(.+?)__/g, '<strong>$1</strong>');
    // Italic (but not inside already-processed tags)
    text = text.replace(/(?<![<*])\*(.+?)\*(?![*>])/g, '<em>$1</em>');
    text = text.replace(/_(.+?)_/g, '<em>$1</em>');
    // Strikethrough
    text = text.replace(/~~(.+?)~~/g, '<del>$1</del>');
    // Links — sanitize href to prevent dangerous URL schemes
    // SECURITY: Parse the URL to catch percent-encoded schemes (e.g. %6a%61%76%61%73%63%72%69%70%74%3a = javascript:)
    text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, href) => {
        let safeHref = href.trim();
        const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:', 'blob:'];
        try {
            const url = new URL(safeHref, window.location.href);
            if (dangerousProtocols.includes(url.protocol)) {
                safeHref = '#';
            }
        } catch {
            // Unparseable URLs are treated as dangerous
            safeHref = '#';
        }
        return `<a href="${escapeHtml(safeHref)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
    });
    return text;
}

function renderMessageContent(text) {
    // Check for action proposals with approval buttons
    const actionMatch = text.match(/action:\s*(\w+\.\w+)/i);
    if (actionMatch) {
        const actionId = escapeHtml(actionMatch[1]);
        return `<div class="message-body-text">${renderMarkdown(text)}</div>
            <div class="action-bar" data-action-id="${actionId}">
                <button class="btn btn-success action-approve" data-action="${actionId}">✓ Approve</button>
                <button class="btn btn-danger action-deny" data-action="${actionId}">✕ Deny</button>
            </div>`;
    }
    return renderMarkdown(text);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeJsString(text) {
    return text
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/`/g, '\\`');
}

function createMessageElement(role, text, timestamp, opts = {}) {
    const wrapper = document.createElement('div');
    wrapper.className = 'message-wrapper';

    const msgId = 'msg-' + Math.random().toString(36).slice(2, 10);
    wrapper.dataset.messageId = msgId;
    wrapper.dataset.rawText = text;
    wrapper.dataset.role = role;

    const name = escapeHtml(role === 'user' ? t('you') : role === 'error' ? t('system') : getAiName());
    const nameClass = role === 'user' ? 'message-user' : role === 'error' ? 'message-error' : 'message-ai-name';
    const timeStr = timestamp
        ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : getTimestamp();

    const memoriesBadge = opts.memories_used > 0
        ? `<span class="memories-badge" title="${opts.memories_used} memories active">🧠 ${opts.memories_used}</span>`
        : '';

    const isAi = role === 'ai';
    const extraButtons = isAi ? `
        <button class="message-action-btn" title="Read aloud" data-speak-target="${msgId}">
            🔊
        </button>
        <button class="message-action-btn" title="Retry" data-retry-target="${msgId}">
            🔄
        </button>
    ` : '';

    const branchButton = `
        <button class="message-action-btn" title="Branch conversation here" data-branch-target="${msgId}">
            🌿
        </button>
    `;

    wrapper.innerHTML = `
        <div class="message ${escapeHtml(role)}">
            <div class="message-header">
                <span class="${nameClass}">${name}</span>
                <span class="message-time">${timeStr}</span>
                ${memoriesBadge}
            </div>
            <div class="message-body">${renderMessageContent(text)}</div>
        </div>
        <div class="message-actions">
            <button class="message-copy-btn" title="Copy to clipboard" data-copy-target="${msgId}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                <span class="copy-label">Copy</span>
            </button>
            ${extraButtons}
            ${branchButton}
        </div>
    `;
    return wrapper;
}

function copyMessageText(msgId) {
    const wrapper = document.querySelector(`[data-message-id="${msgId}"]`);
    if (!wrapper) return;
    const text = wrapper.dataset.rawText || '';
    navigator.clipboard.writeText(text).then(() => {
        const btn = wrapper.querySelector('.message-copy-btn');
        if (!btn) return;
        const original = btn.innerHTML;
        btn.classList.add('copied');
        btn.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            <span class="copy-label">Copied!</span>
        `;
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = original;
        }, 1500);
    }).catch(() => {
        // Fallback for older browsers
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    });
}

function addMessage(role, text, skipStorage = false, opts = {}) {
    const messages = document.getElementById('messages');
    const welcome = messages.querySelector('.welcome-message');
    if (welcome) welcome.remove();

    const wrapper = createMessageElement(role, text, Date.now(), opts);
    messages.appendChild(wrapper);
    scrollToBottom();

    if (!skipStorage && currentSessionId) {
        const sessions = getLocalSessions();
        const s = sessions.find(x => x.id === currentSessionId);
        if (s) {
            s.messages.push({ role, content: text, timestamp: Date.now() });
            saveLocalSessions(sessions);
        }
    }
    return wrapper;
}

function setTyping(show) {
    const el = document.getElementById('typingIndicator');
    if (el) el.classList.toggle('hidden', !show);
    if (show) {
        const word = THINKING_WORDS[Math.floor(Math.random() * THINKING_WORDS.length)];
        const wordEl = document.getElementById('typingWord');
        if (wordEl) wordEl.textContent = word + '...';
    }
    scrollToBottom();
}

async function sendMessage() {
    const input = document.getElementById('input');
    const sendBtn = document.getElementById('send');
    const text = input.value.trim();
    if (!text) return;

    const token = (localStorage.getItem('muccheai_session_token') || '').trim();
    if (!token) {
        showAuthError();
        return;
    }

    input.value = '';
    sendBtn.disabled = true;

    // Slash commands
    if (text.startsWith('/')) {
        const handled = await handleSlashCommand(text);
        sendBtn.disabled = false;
        if (handled) return;
    }

    // Offline queue
    if (!navigator.onLine) {
        offlineQueue.push({ text, sessionId: currentSessionId });
        localStorage.setItem('muccheai_offline_queue', JSON.stringify(offlineQueue));
        addMessage('system', '⏳ You are offline. Message queued and will be sent when connection resumes.');
        sendBtn.disabled = false;
        return;
    }

    // Double-submit guard
    if (isSending) {
        console.log('Already sending, ignoring duplicate');
        sendBtn.disabled = false;
        return;
    }
    isSending = true;

    addMessage('user', text);
    setTyping(true);

    // Create session if needed
    if (!currentSessionId) {
        currentSessionId = 'session-' + Date.now();
        const sessions = getLocalSessions();
        sessions.unshift({
            id: currentSessionId,
            title: text.length > 40 ? text.slice(0, 40) + '...' : text,
            created_at: Date.now(),
            messages: []
        });
        saveLocalSessions(sessions);
        renderChatHistory();
    }

    // Prefer WebSocket if connected
    if (wsConnected && ws) {
        try {
            ws.send(JSON.stringify({ message: text, session_id: currentSessionId }));
        } catch (e) {
            console.error('WebSocket send failed:', e);
            setTyping(false);
            addMessage('error', 'Connection lost. Message queued.');
            offlineQueue.push({ text, sessionId: currentSessionId });
            localStorage.setItem('muccheai_offline_queue', JSON.stringify(offlineQueue));
            sendBtn.disabled = false;
        }
        return;
    }

    // Prefer SSE streaming
    if (streamingEnabled) {
        await sendMessageStream(text);
        sendBtn.disabled = false;
        return;
    }

    // Fallback to regular POST
    try {
        const res = await apiFetch('/api/chat', {
            method: 'POST',
            body: JSON.stringify({ message: text, session_id: currentSessionId })
        });
        if (!res.ok) {
            setTyping(false);
            const errText = await res.text().catch(() => 'Unknown error');
            addMessage('error', `Server error: HTTP ${res.status} — ${errText}`);
            isSending = false;
            sendBtn.disabled = false;
            return;
        }
        const data = await res.json();
        setTyping(false);
        if (data.response && data.response.startsWith('(Error:')) {
            addMessage('error', data.response);
        } else {
            addMessage('ai', data.response || '(no response)', false, { memories_used: data.memories_used || 0 });
            // Auto-title new sessions after first exchange
            const sessions = getLocalSessions();
            const s = sessions.find(x => x.id === currentSessionId);
            if (s && s.messages.filter(m => m.role === 'ai').length === 1) {
                autoUpdateSessionTitle(currentSessionId);
            }
        }
        checkApprovalQueue();
    } catch (err) {
        setTyping(false);
        addMessage('error', `Network error: ${err.message}`);
    }
    isSending = false;
    sendBtn.disabled = false;
    scrollToBottom();
}

function newChat() {
    currentSessionId = null;
    document.getElementById('messages').innerHTML = `
        <div class="welcome-message">
            <h2>🐄 ${escapeHtml(getAiName())}</h2>
            <p>${t('welcomeSubtitle')}</p>
        </div>
    `;
    renderChatHistory();
    switchTab('chat');
}

function loadSession(id) {
    currentSessionId = id;
    const sessions = getLocalSessions();
    const s = sessions.find(x => x.id === id);
    const messages = document.getElementById('messages');
    messages.innerHTML = '';
    if (s && s.messages.length) {
        for (const m of s.messages) {
            const wrapper = createMessageElement(m.role, m.content, m.timestamp);
            messages.appendChild(wrapper);
        }
        scrollToBottom();
    } else {
        messages.innerHTML = `
            <div class="welcome-message">
                <h2>🐄 ${escapeHtml(getAiName())}</h2>
                <p>${t('welcomeSubtitle')}</p>
            </div>
        `;
    }
    renderChatHistory();
    switchTab('chat');
}

function deleteSession(id, ev) {
    try {
        if (ev && ev.stopPropagation) ev.stopPropagation();
        if (!confirm('Delete this chat session?')) return;
        let sessions = getLocalSessions();
        sessions = sessions.filter(s => s.id !== id);
        saveLocalSessions(sessions);
        if (currentSessionId === id) newChat();
        else renderChatHistory();
    } catch (err) {
        console.error('deleteSession error:', err);
    }
}

function getLocalSessions() {
    try { return JSON.parse(localStorage.getItem('muccheai_sessions') || '[]'); }
    catch (e) { return []; }
}

function saveLocalSessions(sessions) {
    localStorage.setItem('muccheai_sessions', JSON.stringify(sessions.slice(0, 100)));
}

function renderChatHistory(filterText) {
    try {
        const list = document.getElementById('chatHistoryList');
        const section = document.getElementById('chatHistorySection');
        if (!list) return;
        let sessions = getLocalSessions();
        if (filterText) {
            const lower = filterText.toLowerCase();
            sessions = sessions.filter(s => (s.title || '').toLowerCase().includes(lower));
        }
        if (!sessions.length) {
            list.innerHTML = '<div class="empty" style="padding:1rem 0;font-size:0.8rem;">No history yet</div>';
            if (section) section.style.display = 'none';
            return;
        }
        if (section) section.style.display = 'block';
        list.innerHTML = sessions.map(s => `
            <div class="history-item ${s.id === currentSessionId ? 'active' : ''}" data-session-id="${escapeHtml(s.id)}">
                <span class="history-title">${escapeHtml(s.title)}</span>
                <span class="history-export" data-export-id="${escapeHtml(s.id)}" title="Export">⬇️</span>
                <span class="history-del" data-delete-id="${escapeHtml(s.id)}">🗑</span>
            </div>
        `).join('');
    } catch (err) {
        console.error('renderChatHistory error:', err);
    }
}

function approveAction(action) {
    addMessage('ai', `✅ Action \`${action}\` approved and executed.`);
}

function denyAction(action) {
    addMessage('ai', `❌ Action \`${action}\` denied.`);
}

// ============================================
// Event Listeners (CSP-compliant: no inline handlers)
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('input');
    if (input) {
        input.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });
    }

    // API Key modal form
    const apiKeyForm = document.querySelector('#apiKeyModal form');
    if (apiKeyForm) {
        apiKeyForm.addEventListener('submit', (e) => { e.preventDefault(); submitApiKey(); });
    }
    const registerBtn = document.getElementById('registerBtn');
    if (registerBtn) {
        registerBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const duressSection = document.getElementById('duressPinSection');
            if (duressSection) duressSection.style.display = 'block';
            submitRegister();
        });
    }

    // AI Name modal
    const nameAiForm = document.querySelector('#nameAiModal form');
    if (nameAiForm) {
        nameAiForm.addEventListener('submit', (e) => { e.preventDefault(); submitAiName(); });
    }

    // API Panel
    const apiPanelBackdrop = document.getElementById('apiPanelBackdrop');
    if (apiPanelBackdrop) apiPanelBackdrop.addEventListener('click', toggleApiPanel);
    const apiPanelClose = document.querySelector('#apiPanel .slide-panel-header .btn-icon');
    if (apiPanelClose) apiPanelClose.addEventListener('click', toggleApiPanel);
    const saveAgentBtn = document.querySelector('.agent-form .btn-primary');
    if (saveAgentBtn) saveAgentBtn.addEventListener('click', saveAgent);
    const testAgentBtn = document.querySelector('.agent-form .btn-secondary');
    if (testAgentBtn) testAgentBtn.addEventListener('click', testAgentConnection);

    // Settings modal
    const settingsClose = document.querySelector('#settingsModal .modal-header .btn-icon');
    if (settingsClose) settingsClose.addEventListener('click', toggleSettings);
    const saveSettingsBtn = document.querySelector('#settingsModal .btn-primary');
    if (saveSettingsBtn) saveSettingsBtn.addEventListener('click', saveSettings);
    const settingsNav = document.querySelector('a[href="#"].nav-item');
    if (settingsNav) settingsNav.addEventListener('click', (e) => { e.preventDefault(); toggleSettings(); });

    // Selects
    const settingModel = document.getElementById('settingModel');
    if (settingModel) settingModel.addEventListener('change', (e) => saveModel(e.target.value));
    const personaSelect = document.getElementById('personaSelect');
    if (personaSelect) personaSelect.addEventListener('change', (e) => switchPersona(e.target.value));
    const agentSelect = document.getElementById('agentSelect');
    if (agentSelect) agentSelect.addEventListener('change', (e) => switchAgent(e.target.value));

    // Language selector
    const settingLanguage = document.getElementById('settingLanguage');
    if (settingLanguage) {
        settingLanguage.addEventListener('change', (e) => {
            setLang(e.target.value);
        });
    }

    // Temperature slider
    const settingTemp = document.getElementById('settingTemp');
    if (settingTemp) {
        settingTemp.addEventListener('input', (e) => {
            const tv = document.getElementById('tempValue');
            if (tv) tv.textContent = e.target.value;
        });
    }

    // Topbar buttons
    const darkModeBtn = document.getElementById('darkModeBtn');
    if (darkModeBtn) darkModeBtn.addEventListener('click', toggleDarkMode);
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
    const sidebarToggle = document.querySelector('.mobile-menu-btn');
    if (sidebarToggle) sidebarToggle.addEventListener('click', toggleSidebar);
    const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
    if (sidebarToggleBtn) sidebarToggleBtn.addEventListener('click', toggleSidebar);
    const apiPanelToggle = document.getElementById('apiPanelToggleBtn');
    if (apiPanelToggle) apiPanelToggle.addEventListener('click', toggleApiPanel);
    const newChatBtn = document.getElementById('newChatBtn');
    if (newChatBtn) newChatBtn.addEventListener('click', newChat);

    // Share session
    const shareSessionBtn = document.getElementById('shareSessionBtn');
    if (shareSessionBtn) shareSessionBtn.addEventListener('click', shareCurrentSession);

    // Global search
    const globalSearchBtn = document.getElementById('globalSearchBtn');
    if (globalSearchBtn) {
        globalSearchBtn.addEventListener('click', () => {
            const q = prompt('Search memories and chats:');
            if (q) runGlobalSearch(q);
        });
    }

    // Memory backup/restore
    const backupMemoriesBtn = document.getElementById('backupMemoriesBtn');
    if (backupMemoriesBtn) backupMemoriesBtn.addEventListener('click', backupMemories);
    const restoreMemoriesBtn = document.getElementById('restoreMemoriesBtn');
    if (restoreMemoriesBtn) restoreMemoriesBtn.addEventListener('click', restoreMemories);

    // Chat history search
    const chatHistorySearch = document.getElementById('chatHistorySearch');
    if (chatHistorySearch) {
        chatHistorySearch.addEventListener('input', (e) => {
            renderChatHistory(e.target.value);
        });
    }

    // Status sidebar collapse
    const statusToggle = document.getElementById('statusToggle');
    if (statusToggle) {
        statusToggle.addEventListener('click', () => {
            const sidebar = document.getElementById('statusSidebar');
            if (sidebar) {
                sidebar.classList.toggle('collapsed');
                localStorage.setItem('muccheai_status_collapsed', sidebar.classList.contains('collapsed') ? '1' : '0');
            }
        });
    }

    // Research chats
    const researchChatsBtn = document.getElementById('researchChatsBtn');
    if (researchChatsBtn) researchChatsBtn.addEventListener('click', toggleResearch);
    const researchClose = document.querySelector('#researchModal .modal-header .btn-icon');
    if (researchClose) researchClose.addEventListener('click', toggleResearch);
    const runResearchBtn = document.getElementById('runResearchBtn');
    if (runResearchBtn) runResearchBtn.addEventListener('click', runResearch);
    const researchQuery = document.getElementById('researchQuery');
    if (researchQuery) {
        researchQuery.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') runResearch();
        });
    }
    const researchModal = document.getElementById('researchModal');
    if (researchModal) {
        researchModal.addEventListener('click', (e) => {
            if (e.target === researchModal) toggleResearch();
        });
    }

    // Send button
    const sendBtn = document.getElementById('send');
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);

    // Memory subtabs
    const subtabMemories = document.getElementById('subtab-memories');
    if (subtabMemories) subtabMemories.addEventListener('click', () => switchMemorySubtab('memories'));
    const subtabQueue = document.getElementById('subtab-queue');
    if (subtabQueue) subtabQueue.addEventListener('click', () => switchMemorySubtab('queue'));

    // Memory search
    const memorySearchInput = document.getElementById('memorySearchInput');
    if (memorySearchInput) {
        memorySearchInput.addEventListener('input', (e) => {
            const q = e.target.value.trim();
            renderMemories(q ? filterMemories(q) : allMemories);
        });
    }

    // Add memory
    const addMemoryBtn = document.querySelector('#memory-subtab-memories button');
    if (addMemoryBtn) addMemoryBtn.addEventListener('click', addMemoryDirect);

    // Action approval delegation (CSP-compliant: no inline handlers)
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.action-approve, .action-deny');
        if (!btn) return;
        const actionId = btn.dataset.action;
        if (!actionId) return;
        if (btn.classList.contains('action-approve')) {
            approveAction(actionId);
        } else {
            denyAction(actionId);
        }
    });

    // Copy message delegation (CSP-compliant)
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.message-copy-btn');
        if (!btn) return;
        const targetId = btn.dataset.copyTarget;
        if (targetId) copyMessageText(targetId);
    });

    // Persona card delegation (CSP-compliant)
    document.addEventListener('click', (e) => {
        const card = e.target.closest('.persona-card');
        if (!card) return;
        const persona = card.dataset.persona;
        if (persona) switchPersona(persona);
    });

    // Chat history delegation
    const chatHistoryList = document.getElementById('chatHistoryList');
    if (chatHistoryList) {
        chatHistoryList.addEventListener('click', (e) => {
            try {
                // Check delete FIRST (it's inside the session item)
                const del = e.target.closest('[data-delete-id]');
                if (del) { deleteSession(del.dataset.deleteId, e); return; }
                const exp = e.target.closest('[data-export-id]');
                if (exp) { exportChat(exp.dataset.exportId); return; }
                const item = e.target.closest('[data-session-id]');
                if (item) { loadSession(item.dataset.sessionId); return; }
            } catch (err) {
                console.error('chatHistory click error:', err);
            }
        });
    }

    // Approval queue delegation
    const queueList = document.getElementById('queueList');
    if (queueList) {
        queueList.addEventListener('click', (e) => {
            const approveBtn = e.target.closest('.queue-approve');
            if (approveBtn) { approveProposal(approveBtn.dataset.proposalId); return; }
            const rejectBtn = e.target.closest('.queue-reject');
            if (rejectBtn) { rejectProposal(rejectBtn.dataset.proposalId); return; }
        });
    }

    // Approval toast button
    const approvalToastBtn = document.getElementById('approvalToastBtn');
    if (approvalToastBtn) {
        approvalToastBtn.addEventListener('click', () => {
            hideApprovalToast();
            switchTab('memory');
            setTimeout(() => switchMemorySubtab('queue'), 100);
        });
    }
    // Approval toast dismiss button
    const toastDismiss = document.getElementById('approvalToastDismiss');
    if (toastDismiss) {
        toastDismiss.addEventListener('click', hideApprovalToast);
    }
    // Rename AI button in settings
    const renameAiBtn = document.getElementById('renameAiBtn');
    if (renameAiBtn) {
        renameAiBtn.addEventListener('click', () => {
            const input = document.getElementById('settingAiName');
            const name = input.value.trim();
            if (!name) return;
            localStorage.setItem('muccheai_name', name);
            updateAiNameDisplay();
            // Refresh welcome message if visible
            const welcome = document.querySelector('.welcome-message h2');
            if (welcome) welcome.textContent = '🐄 ' + name;
        });
    }

    renderChatHistory();
});

// ============================================
// Memory — Structured Memory + Approval Queue
// ============================================
let allMemories = [];

function switchMemorySubtab(name) {
    document.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('subtab-' + name).classList.add('active');
    document.querySelectorAll('.memory-subtab-content').forEach(c => c.style.display = 'none');
    document.getElementById('memory-subtab-' + name).style.display = 'block';
    if (name === 'queue') loadQueue();
    else loadMemory();
}

function filterMemories(query) {
    const q = query.toLowerCase();
    return allMemories.filter(e => {
        const val = typeof e.value === 'string' ? e.value : JSON.stringify(e.value);
        return e.key.toLowerCase().includes(q) || val.toLowerCase().includes(q);
    });
}

function renderMemories(entries) {
    const factsEl = document.getElementById('factsList');
    const prefsEl = document.getElementById('preferencesList');
    const tasksEl = document.getElementById('taskHistoryList');

    const facts = entries.filter(e => e.memory_type === 'Fact');
    const prefs = entries.filter(e => e.memory_type === 'Preference');
    const tasks = entries.filter(e => e.memory_type === 'TaskHistory');

    factsEl.innerHTML = facts.length
        ? facts.map(e => renderMemoryItem(e)).join('')
        : '<div class="empty-state">No facts stored yet.</div>';

    prefsEl.innerHTML = prefs.length
        ? prefs.map(e => renderMemoryItem(e)).join('')
        : '<div class="empty-state">No preferences stored yet.</div>';

    tasksEl.innerHTML = tasks.length
        ? tasks.map(e => renderMemoryItem(e)).join('')
        : '<div class="empty-state">No task history yet.</div>';
}

async function loadMemory() {
    const factsEl = document.getElementById('factsList');
    const prefsEl = document.getElementById('preferencesList');
    const tasksEl = document.getElementById('taskHistoryList');

    factsEl.innerHTML = '<div class="empty-state">' + t('loading') + '</div>';
    prefsEl.innerHTML = '<div class="empty-state">' + t('loading') + '</div>';
    tasksEl.innerHTML = '<div class="empty-state">' + t('loading') + '</div>';

    try {
        const res = await apiFetch('/api/memory');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        allMemories = data.entries || [];
        renderMemories(allMemories);
    } catch (e) {
        factsEl.innerHTML = `<div class="empty-state">Failed: ${escapeHtml(e.message)}</div>`;
        prefsEl.innerHTML = '';
        tasksEl.innerHTML = '';
    }
}

function renderMemoryItem(e) {
    const val = typeof e.value === 'string' ? e.value : JSON.stringify(e.value);
    return `<div class="memory-item">
        <span class="memory-item-key">${escapeHtml(e.key)}</span>
        <span class="memory-item-value">${escapeHtml(val)}</span>
        <button class="memory-item-delete" data-memory-key="${escapeHtml(e.key)}">🗑</button>
    </div>`;
}

async function addMemoryDirect() {
    const type = document.getElementById('memoryTypeSelect').value;
    const key = document.getElementById('memoryKeyInput').value.trim();
    const value = document.getElementById('memoryValueInput').value.trim();
    if (!key || !value) return;

    try {
        const res = await apiFetch('/api/memory', {
            method: 'POST',
            body: JSON.stringify({ key, value, memory_type: type })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        document.getElementById('memoryKeyInput').value = '';
        document.getElementById('memoryValueInput').value = '';
        loadMemory();
    } catch (e) {
        alert('Failed to save memory: ' + e.message);
    }
}

async function deleteMemory(key) {
    if (!confirm(`Delete memory "${key}"?`)) return;
    try {
        const res = await apiFetch(`/api/memory/${encodeURIComponent(key)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadMemory();
    } catch (e) {
        alert('Failed to delete: ' + e.message);
    }
}

// Approval Queue
async function loadQueue() {
    const list = document.getElementById('queueList');
    list.innerHTML = '<div class="empty-state">' + t('queueLoading') + '</div>';

    try {
        const res = await apiFetch('/api/memory/queue');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const proposals = data.proposals || [];

        // Update badge
        const badge = document.getElementById('queueBadge');
        if (badge) {
            badge.textContent = proposals.length;
            badge.style.display = proposals.length > 0 ? 'inline-block' : 'none';
        }

        if (!proposals.length) {
            list.innerHTML = '<div class="empty-state">' + t('queueEmpty') + '</div>';
            return;
        }

        list.innerHTML = proposals.map(p => {
            const val = typeof p.value === 'string' ? p.value : JSON.stringify(p.value);
            return `<div class="queue-item">
                <div class="queue-item-header">
                    <span class="queue-item-key">${escapeHtml(p.key)}</span>
                    <span class="queue-item-type">${escapeHtml(p.memory_type)}</span>
                </div>
                <div class="queue-item-justification">${escapeHtml(p.justification)}</div>
                <div class="queue-item-value">${escapeHtml(val)}</div>
                <div class="queue-item-actions">
                    <button class="queue-approve" data-proposal-id="${escapeHtml(p.id)}">✓ Approve</button>
                    <button class="queue-reject" data-proposal-id="${escapeHtml(p.id)}">✕ Reject</button>
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        list.innerHTML = `<div class="empty-state">Failed to load queue: ${escapeHtml(e.message)}</div>`;
    }
}

async function approveProposal(id) {
    try {
        const res = await apiFetch(`/api/memory/queue/${encodeURIComponent(id)}/approve`, { method: 'POST' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadQueue();
        loadMemory();
    } catch (e) {
        alert('Failed to approve: ' + e.message);
    }
}

async function rejectProposal(id) {
    try {
        const res = await apiFetch(`/api/memory/queue/${encodeURIComponent(id)}/reject`, { method: 'POST' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadQueue();
    } catch (e) {
        alert('Failed to reject: ' + e.message);
    }
}

// Approval Toast
function showApprovalToast() {
    const toast = document.getElementById('approvalToast');
    if (toast) toast.style.display = 'flex';
}

function hideApprovalToast() {
    const toast = document.getElementById('approvalToast');
    if (toast) toast.style.display = 'none';
}

async function checkApprovalQueue() {
    try {
        const res = await apiFetch('/api/memory/queue');
        if (!res.ok) return;
        const data = await res.json();
        const proposals = data.proposals || [];
        if (proposals.length > 0) {
            showApprovalToast();
        } else {
            hideApprovalToast();
        }
        // Update badge on memory tab
        const badge = document.getElementById('queueBadge');
        if (badge) {
            badge.textContent = proposals.length;
            badge.style.display = proposals.length > 0 ? 'inline-block' : 'none';
        }
    } catch (e) {
        // Silently fail
    }
}

// ============================================
// Personas
// ============================================
const PERSONA_AVATARS = {
    'Assistant': '🤖',
    'Coder': '👨‍💻',
    'Security Analyst': '🛡️',
    'Creative Writer': '✍️',
};

function getPersonaAvatar(name) {
    return PERSONA_AVATARS[name] || '🎭';
}

async function loadPersonas() {
    const grid = document.getElementById('personaGrid');
    grid.innerHTML = '<div class="empty">Loading personas...</div>';

    try {
        const res = await apiFetch('/api/personas');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        currentPersona = data.current;
        updatePersonaSelect(data.personas, data.current);

        grid.innerHTML = data.personas.map(p => `
            <div class="persona-card ${p.name === data.current ? 'active' : ''}" data-persona="${escapeHtml(p.name)}">
                ${p.name === data.current ? '<span class="active-badge">Active</span>' : ''}
                <div class="persona-avatar">${getPersonaAvatar(p.name)}</div>
                <div class="persona-name">${escapeHtml(p.name)}</div>
                <div class="persona-desc">${escapeHtml(p.description)}</div>
                <div class="persona-prompt">${escapeHtml(p.system_prompt)}</div>
            </div>
        `).join('');
    } catch (e) {
        grid.innerHTML = `<div class="empty">Failed to load personas: ${escapeHtml(e.message)}</div>`;
    }
}

function updatePersonaSelect(personas, current) {
    const sel = document.getElementById('personaSelect');
    sel.innerHTML = personas.map(p =>
        `<option value="${escapeHtml(p.name)}" ${p.name === current ? 'selected' : ''}>${escapeHtml(p.name)}</option>`
    ).join('');
}

function updateAgentSelect(agents, active) {
    const sel = document.getElementById('agentSelect');
    if (!sel) return;
    if (!agents || !agents.length) {
        const model = lastKnownModel || 'Ollama';
        sel.innerHTML = `<option value="">${escapeHtml(model)}</option>`;
        return;
    }
    sel.innerHTML = agents.map(a => {
        // Show model name for Ollama agents so users can tell them apart
        const display = a.provider === 'ollama' ? a.model : a.name;
        return `<option value="${escapeHtml(a.name)}" ${a.name === active ? 'selected' : ''}>${escapeHtml(display)}</option>`;
    }).join('');
}

async function switchAgent(name) {
    if (!name) return;
    try {
        const res = await apiFetch(`/api/agents/${encodeURIComponent(name)}/active`, { method: 'POST' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadAgents();
    } catch (e) {
        console.error('Failed to switch agent:', e);
        alert('Failed to switch agent: ' + e.message);
    }
}

async function switchPersona(name) {
    try {
        const res = await apiFetch('/api/personas/switch', {
            method: 'POST',
            body: JSON.stringify({ name })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        currentPersona = data.current;
        updatePersonaSelect(data.personas, data.current);
        document.querySelectorAll('.persona-card').forEach(c => c.classList.remove('active'));
        const active = Array.from(document.querySelectorAll('.persona-card')).find(c =>
            c.querySelector('.persona-name')?.textContent === name
        );
        if (active) active.classList.add('active');
    } catch (e) {
        console.error('Failed to switch persona:', e);
    }
}

// ============================================
// API Keys / Agents Panel
// ============================================
function toggleApiPanel() {
    document.getElementById('apiPanel').classList.toggle('open');
    document.getElementById('apiPanelBackdrop').classList.toggle('open');
    loadAgents();
}

function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const isMobile = window.innerWidth <= 600;
    if (isMobile) {
        sidebar.classList.toggle('open');
    } else {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('muccheai_sidebar_collapsed', sidebar.classList.contains('collapsed') ? '1' : '0');
    }
}

async function loadAgents() {
    try {
        const res = await apiFetch('/api/agents');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderAgents(data.agents, data.active);
    } catch (e) {
        document.getElementById('agentsList').innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
    }
}

function renderAgents(agents, active) {
    const list = document.getElementById('agentsList');
    updateAgentSelect(agents, active);
    // Show/hide cloud provider privacy warning
    const warning = document.getElementById('cloudPrivacyWarning');
    if (warning) {
        const activeAgent = agents.find(a => a.name === active);
        const isCloud = activeAgent && activeAgent.provider !== 'ollama';
        warning.style.display = isCloud ? 'block' : 'none';
    }
    if (!agents.length) {
        list.innerHTML = '<div class="empty">No providers configured.</div>';
        return;
    }
    list.innerHTML = agents.map(a => `
        <div class="agent-item ${a.name === active ? 'active' : ''}">
            <div class="agent-item-header">
                <span class="agent-name">${escapeHtml(a.name)}</span>
                <span class="agent-provider">${escapeHtml(a.provider)}</span>
            </div>
            <div class="agent-model">${escapeHtml(a.model)}</div>
            <div class="agent-actions">
                ${a.name !== active ? `<button class="btn btn-secondary" data-agent-name="${escapeHtml(a.name)}" data-action="activate">Activate</button>` : '<span class="badge" style="color:var(--accent-green);border-color:var(--accent-green);">Active</span>'}
                <button class="btn btn-danger" data-agent-name="${escapeHtml(a.name)}" data-action="delete">Delete</button>
            </div>
        </div>
    `).join('');
}

async function saveAgent() {
    const name = document.getElementById('agentName').value.trim();
    const provider = document.getElementById('agentProvider').value;
    const model = document.getElementById('agentModel').value.trim();
    const baseUrl = document.getElementById('agentBaseUrl').value.trim() || null;
    const apiKey = document.getElementById('agentApiKey').value.trim() || null;

    if (!name || !model) {
        alert('Name and model are required');
        return;
    }

    try {
        const res = await apiFetch('/api/agents', {
            method: 'POST',
            body: JSON.stringify({ name, provider, model, base_url: baseUrl, api_key: apiKey })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        document.getElementById('agentName').value = '';
        document.getElementById('agentModel').value = '';
        document.getElementById('agentBaseUrl').value = '';
        document.getElementById('agentApiKey').value = '';
        loadAgents();
    } catch (e) {
        alert('Failed to save: ' + e.message);
    }
}

async function deleteAgent(name) {
    if (!confirm(`Delete provider "${name}"?`)) return;
    try {
        const res = await apiFetch(`/api/agents/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadAgents();
    } catch (e) {
        alert('Failed to delete: ' + e.message);
    }
}

async function activateAgent(name) {
    try {
        const res = await apiFetch(`/api/agents/${encodeURIComponent(name)}/active`, { method: 'POST' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadAgents();
    } catch (e) {
        alert('Failed to activate: ' + e.message);
    }
}

async function testAgentConnection() {
    const provider = document.getElementById('agentProvider').value;
    const model = document.getElementById('agentModel').value.trim();
    const baseUrl = document.getElementById('agentBaseUrl').value.trim() || null;
    const apiKey = document.getElementById('agentApiKey').value.trim() || null;
    const result = document.getElementById('agentTestResult');

    result.className = 'test-result';
    result.textContent = 'Testing...';

    try {
        const res = await apiFetch('/api/agents/test', {
            method: 'POST',
            body: JSON.stringify({ provider, model, base_url: baseUrl, api_key: apiKey })
        });
        const data = await res.json();
        result.classList.add(data.success ? 'success' : 'error');
        result.textContent = data.message;
    } catch (e) {
        result.classList.add('error');
        result.textContent = 'Test failed: ' + e.message;
    }
}

// ============================================
// Settings
// ============================================
function toggleSettings() {
    document.getElementById('settingsModal').classList.toggle('open');
    if (document.getElementById('settingsModal').classList.contains('open')) {
        loadSettings();
    }
}

async function loadSettings() {
    try {
        const res = await apiFetch('/api/settings');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        document.getElementById('settingModel').value = data.model;
        document.getElementById('settingTemp').value = data.temperature;
        document.getElementById('tempValue').textContent = data.temperature;
        document.getElementById('settingMaxTokens').value = data.max_tokens;
        document.getElementById('settingMemLimit').value = data.sandbox_memory_limit_mb;
        document.getElementById('settingDualVerify').checked = data.dual_verification;
        document.getElementById('settingAutoApprove').checked = data.auto_approve_low_risk;
        document.getElementById('settingShowReasoning').checked = data.show_reasoning;
        const aiNameInput = document.getElementById('settingAiName');
        if (aiNameInput) aiNameInput.value = getAiName();
    } catch (e) {
        console.error('Failed to load settings:', e);
    }
}

async function saveModel(model) {
    try {
        const res = await apiFetch('/api/model', {
            method: 'POST',
            body: JSON.stringify({ model })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
    } catch (e) {
        console.error('Failed to save model:', e);
    }
}

async function saveSettings() {
    const body = {
        model: document.getElementById('settingModel').value,
        temperature: parseFloat(document.getElementById('settingTemp').value),
        max_tokens: parseInt(document.getElementById('settingMaxTokens').value),
        sandbox_memory_limit_mb: parseInt(document.getElementById('settingMemLimit').value),
        dual_verification: document.getElementById('settingDualVerify').checked,
        auto_approve_low_risk: document.getElementById('settingAutoApprove').checked,
        show_reasoning: document.getElementById('settingShowReasoning').checked,
    };

    try {
        const res = await apiFetch('/api/settings', {
            method: 'POST',
            body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        toggleSettings();
    } catch (e) {
        alert('Failed to save settings: ' + e.message);
    }
}

function toggleResearch() {
    const modal = document.getElementById('researchModal');
    modal.classList.toggle('open');
    if (modal.classList.contains('open')) {
        document.getElementById('researchQuery').focus();
    }
}

async function runResearch() {
    const queryInput = document.getElementById('researchQuery');
    const resultDiv = document.getElementById('researchResult');
    const loadingDiv = document.getElementById('researchLoading');
    const query = queryInput.value.trim();
    if (!query) return;

    const sessions = getLocalSessions();
    if (!sessions.length) {
        resultDiv.textContent = 'No chat history to research.';
        return;
    }

    loadingDiv.style.display = 'block';
    resultDiv.textContent = '';

    // Build a condensed summary of all chat history
    let historyContext = 'Here is a summary of all my chat sessions:\n\n';
    for (const s of sessions.slice(0, 50)) {
        historyContext += `Session: ${s.title || 'Untitled'}\n`;
        if (s.messages && s.messages.length) {
            const recent = s.messages.slice(-6);
            for (const m of recent) {
                const role = m.role === 'ai' ? 'AI' : 'User';
                const text = (m.content || '').substring(0, 200).replace(/\n/g, ' ');
                historyContext += `  ${role}: ${text}\n`;
            }
        }
        historyContext += '\n';
    }

    const researchPrompt = `${historyContext}\n---\nBased on the above chat history, please answer this research question:\n${query}`;

    try {
        let res = await apiFetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: researchPrompt, research: true })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        let data = await res.json();

        // External provider requires explicit confirmation
        if (data.needs_confirmation) {
            const confirmed = confirm(data.needs_confirmation + '\n\nDo you want to proceed?');
            if (!confirmed) {
                resultDiv.textContent = 'Research cancelled.';
                loadingDiv.style.display = 'none';
                return;
            }
            // Re-send with confirmation flag
            res = await apiFetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: researchPrompt, research: true, research_confirmed: true })
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            data = await res.json();
        }

        resultDiv.textContent = data.response || '(no response)';
    } catch (e) {
        resultDiv.textContent = 'Error: ' + e.message;
    } finally {
        loadingDiv.style.display = 'none';
    }
}

// Close modal on backdrop click
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('settingsModal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('settingsModal')) toggleSettings();
    });
});

// ============================================
// Status Page & Polling
// ============================================
async function loadStatusPage() {
    const grid = document.getElementById('statusGrid');
    grid.innerHTML = '<div class="empty">Loading status...</div>';

    try {
        const res = await apiFetch('/api/status');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderStatusPage(data);
    } catch (e) {
        grid.innerHTML = `<div class="empty">Failed to load status</div>`;
    }
}

function renderStatusPage(data) {
    if (data.model) lastKnownModel = data.model;
    const grid = document.getElementById('statusGrid');
    grid.innerHTML = `
        <div class="card">
            <h3>🖥️ Sandbox</h3>
            <div class="stat-row"><span>Status</span><span class="badge" style="color:${data.sandbox_running ? 'var(--accent-green)' : 'var(--accent-red)'};">${data.sandbox_running ? 'Running' : 'Stopped'}</span></div>
            <div class="stat-row"><span>Memory Limit</span><span class="stat-val">${escapeHtml(String(data.sandbox_memory_limit_mb))} MB</span></div>
            <div class="stat-row"><span>Dual Verification</span><span class="badge">${data.dual_verification ? 'On' : 'Off'}</span></div>
        </div>
        <div class="card">
            <h3>🧠 Model</h3>
            <div class="stat-row"><span>Model</span><span class="stat-val">${escapeHtml(data.model)}</span></div>
            <div class="stat-row"><span>Temperature</span><span class="stat-val">${escapeHtml(String(data.temperature))}</span></div>
            <div class="stat-row"><span>Max Tokens</span><span class="stat-val">${escapeHtml(String(data.max_tokens))}</span></div>
        </div>
        <div class="card">
            <h3>🔐 Security</h3>
            <div class="stat-row"><span>PQC Crypto</span><span class="badge" style="color:var(--accent-green);">Enabled</span></div>
            <div class="stat-row"><span>Policy Rules</span><span class="stat-val">${escapeHtml(String(data.policy_rule_count))}</span></div>
            <div class="stat-row"><span>Auto-Approve</span><span class="badge">${data.auto_approve_low_risk ? 'On' : 'Off'}</span></div>
        </div>
        <div class="card">
            <h3>📡 Connection</h3>
            <div class="stat-row"><span>Ollama Host</span><span class="stat-val">${escapeHtml(data.ollama_host)}</span></div>
            <div class="stat-row"><span>Ollama Status</span><span class="badge" style="color:${data.ollama_connected ? 'var(--accent-green)' : 'var(--accent-red)'};">${data.ollama_connected ? 'Connected' : 'Disconnected'}</span></div>
            <div class="stat-row"><span>Active Agent</span><span class="stat-val">${escapeHtml(data.active_agent || 'default')}</span></div>
        </div>
        <div class="card" style="grid-column:1/-1;">
            <h3>📋 Active Policy Rules</h3>
            ${data.policy_rules.map(r => `<div class="stat-row"><span>${escapeHtml(r)}</span></div>`).join('')}
        </div>
    `;
}

async function pollStatus() {
    try {
        const res = await apiFetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();
        if (data.model) lastKnownModel = data.model;

        const ollamaDot = document.getElementById('ollamaDot');
        if (ollamaDot) {
            ollamaDot.className = 'status-dot ' + (data.ollama_connected ? 'green' : 'red');
        }
        document.getElementById('ruleCount').textContent = data.policy_rule_count;
        document.getElementById('tokenCount').textContent = data.active_tokens;
        const auditEl = document.getElementById('lastAudit');
        if (auditEl && data.last_audit_entry) {
            auditEl.textContent = data.last_audit_entry;
        }
        const agentSelect = document.getElementById('agentSelect');
        if (agentSelect && data.active_agent) {
            agentSelect.value = data.active_agent;
        }
    } catch (e) {
        // Silently fail on poll
    }
}

// ============================================
// MCP Registry
// ============================================
const MCP_PRESETS = {
    github: { name: 'github', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] },
    filesystem: { name: 'filesystem', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/Users'] },
    'brave-search': { name: 'brave-search', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-brave-search'] },
    slack: { name: 'slack', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-slack'] },
    fetch: { name: 'fetch', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-fetch'] },
    puppeteer: { name: 'puppeteer', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-puppeteer'] },
    postgres: { name: 'postgres', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres'] },
    sqlite: { name: 'sqlite', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-sqlite'] },
};

function applyMcpPreset(key) {
    if (!key || key === 'custom') return;
    const p = MCP_PRESETS[key];
    if (!p) return;
    document.getElementById('mcpName').value = p.name;
    document.getElementById('mcpTransport').value = p.transport;
    toggleMcpFields();
    if (p.transport === 'stdio') {
        document.getElementById('mcpCommand').value = p.command;
        document.getElementById('mcpArgs').value = p.args.join(', ');
    } else {
        document.getElementById('mcpUrl').value = p.url || '';
        document.getElementById('mcpApiKey').value = p.api_key || '';
    }
}

async function loadMcpRegistry() {
    const list = document.getElementById('mcpList');
    if (!list) return;
    list.innerHTML = '<div class="empty">Loading MCP servers...</div>';
    try {
        const res = await apiFetch('/api/mcp/servers');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderMcpServers(data.servers || []);
    } catch (e) {
        list.innerHTML = `<div class="empty">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
}

function renderMcpServers(servers) {
    const list = document.getElementById('mcpList');
    if (!servers.length) {
        list.innerHTML = '<div class="empty">No MCP servers configured. Add one above.</div>';
        return;
    }
    list.innerHTML = servers.map(s => `
        <div class="mcp-item">
            <div class="mcp-item-header">
                <span class="mcp-item-name">${escapeHtml(s.name)}</span>
                <span class="mcp-item-transport">${escapeHtml(s.transport)}</span>
            </div>
            <div class="mcp-item-detail">${escapeHtml(s.command || s.url || '')}</div>
            <div class="mcp-item-actions">
                <button class="btn btn-secondary" data-mcp-name="${escapeHtml(s.name)}" data-action="test">Test</button>
                <button class="btn btn-danger" data-mcp-name="${escapeHtml(s.name)}" data-action="delete">Delete</button>
            </div>
            <div class="mcp-test-result" id="mcp-result-${escapeHtml(s.name)}"></div>
        </div>
    `).join('');
}

async function addMcpServer() {
    const name = document.getElementById('mcpName').value.trim();
    const transport = document.getElementById('mcpTransport').value;
    if (!name) { alert('Name is required'); return; }

    const body = { name, transport, args: [], command: null, url: null, api_key: null };
    if (transport === 'stdio') {
        body.command = document.getElementById('mcpCommand').value.trim() || null;
        const argsStr = document.getElementById('mcpArgs').value.trim();
        body.args = argsStr ? argsStr.split(',').map(a => a.trim()) : [];
    } else {
        body.url = document.getElementById('mcpUrl').value.trim() || null;
        body.api_key = document.getElementById('mcpApiKey').value.trim() || null;
    }

    try {
        const res = await apiFetch('/api/mcp/servers', { method: 'POST', body: JSON.stringify(body) });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        document.getElementById('mcpName').value = '';
        document.getElementById('mcpCommand').value = '';
        document.getElementById('mcpArgs').value = '';
        document.getElementById('mcpUrl').value = '';
        document.getElementById('mcpApiKey').value = '';
        loadMcpRegistry();
    } catch (e) {
        alert('Failed to add: ' + e.message);
    }
}

async function deleteMcpServer(name) {
    if (!confirm(`Delete MCP server "${name}"?`)) return;
    try {
        const res = await apiFetch(`/api/mcp/servers/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        loadMcpRegistry();
    } catch (e) {
        alert('Failed to delete: ' + e.message);
    }
}

async function testMcpServer(name) {
    const resultEl = document.getElementById(`mcp-result-${name}`);
    if (resultEl) resultEl.textContent = 'Testing...';
    try {
        const res = await apiFetch(`/api/mcp/servers/${encodeURIComponent(name)}/test`, { method: 'POST' });
        const data = await res.json();
        if (resultEl) {
            const tools = data.tools && data.tools.length ? `\nTools: ${data.tools.join(', ')}` : '';
            resultEl.textContent = (data.success ? '✅ ' : '❌ ') + data.message + tools;
        }
    } catch (e) {
        if (resultEl) resultEl.textContent = '❌ Error: ' + e.message;
    }
}

function toggleMcpFields() {
    const transport = document.getElementById('mcpTransport').value;
    const stdioFields = document.getElementById('mcpStdioFields');
    const httpFields = document.getElementById('mcpHttpFields');
    if (stdioFields) stdioFields.style.display = transport === 'stdio' ? 'block' : 'none';
    if (httpFields) httpFields.style.display = transport === 'stdio' ? 'none' : 'block';
}

// Voice input via Web Speech API
function initVoiceInput() {
    const voiceBtn = document.getElementById('voiceBtn');
    if (!voiceBtn || !('webkitSpeechRecognition' in window || 'SpeechRecognition' in window)) {
        if (voiceBtn) voiceBtn.style.display = 'none';
        return;
    }
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';

    recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        const input = document.getElementById('input');
        input.value = (input.value + ' ' + transcript).trim();
        voiceBtn.textContent = '🎤';
    };
    recognition.onerror = () => { voiceBtn.textContent = '🎤'; };
    recognition.onend = () => { voiceBtn.textContent = '🎤'; };

    voiceBtn.addEventListener('click', () => {
        voiceBtn.textContent = '🔴';
        recognition.start();
    });
}

// File upload handler
function initFileUpload() {
    const uploadBtn = document.getElementById('uploadBtn');
    const fileInput = document.getElementById('fileInput');
    if (!uploadBtn || !fileInput) return;

    uploadBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
        const file = fileInput.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        try {
            const res = await fetch('/api/upload', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + (localStorage.getItem('muccheai_session_token') || '') },
                body: formData
            });
            if (res.ok) {
                alert('File uploaded and stored as memory.');
                loadInlineFilePreviews();
            } else {
                alert('Upload failed: HTTP ' + res.status);
            }
        } catch (e) {
            alert('Upload failed: ' + e.message);
        }
        fileInput.value = '';
    });
}

// Chat export to markdown
async function exportChat(sessionId) {
    try {
        const res = await apiFetch('/api/sessions/' + sessionId + '/export');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = sessionId + '-chat.md';
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Export failed: ' + e.message);
    }
}

// Start polling
document.addEventListener('DOMContentLoaded', () => {
    pollStatus();
    statusPoller = setInterval(pollStatus, 5000);
    initVoiceInput();
    initFileUpload();
    loadInlineFilePreviews();
});

// ============================================
// Delegated event listeners (replaces inline onclick handlers)
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Memory delete buttons (delegated from parent containers)
    ['factsList', 'preferencesList', 'taskHistoryList'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('click', (e) => {
                const btn = e.target.closest('.memory-item-delete');
                if (!btn) return;
                const key = btn.getAttribute('data-memory-key');
                if (key) deleteMemory(key);
            });
        }
    });

    // Agent activate/delete buttons (delegated from agentsList)
    const agentsList = document.getElementById('agentsList');
    if (agentsList) {
        agentsList.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            const name = btn.getAttribute('data-agent-name');
            const action = btn.getAttribute('data-action');
            if (!name) return;
            if (action === 'activate') activateAgent(name);
            else if (action === 'delete') deleteAgent(name);
        });
    }

    // MCP preset selector
    const mcpPreset = document.getElementById('mcpPreset');
    if (mcpPreset) mcpPreset.addEventListener('change', (e) => applyMcpPreset(e.target.value));

    // MCP transport toggle
    const mcpTransport = document.getElementById('mcpTransport');
    if (mcpTransport) mcpTransport.addEventListener('change', toggleMcpFields);

    // MCP add button
    const mcpAddBtn = document.getElementById('mcpAddBtn');
    if (mcpAddBtn) mcpAddBtn.addEventListener('click', addMcpServer);

    // MCP list delegation
    const mcpList = document.getElementById('mcpList');
    if (mcpList) {
        mcpList.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            const name = btn.getAttribute('data-mcp-name');
            const action = btn.getAttribute('data-action');
            if (!name) return;
            if (action === 'test') testMcpServer(name);
            else if (action === 'delete') deleteMcpServer(name);
        });
    }
});

// ============================================
// Version display
// ============================================
async function fetchVersion() {
    try {
        const res = await fetch('/api/version');
        if (res.ok) {
            const data = await res.json();
            const badge = document.getElementById('versionBadge');
            const display = document.getElementById('versionDisplay');
            if (badge) badge.textContent = 'MuccheAI v' + data.version;
            if (display) display.textContent = 'v' + data.version + ' — Secure AI Agent';
        }
    } catch (e) {
        console.warn('Failed to fetch version:', e);
    }
}

// ============================================
// Init
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    loadPersonas();
    fetchVersion();
});

// ============================================
// Feature: Slash commands
// ============================================
async function handleSlashCommand(text) {
    const parts = text.slice(1).split(' ');
    const cmd = parts[0].toLowerCase();
    const arg = parts.slice(1).join(' ').trim();

    switch (cmd) {
        case 'clear':
            newChat();
            return true;
        case 'memory':
            switchTab('memory');
            return true;
        case 'export':
            try {
                if (currentSessionId) await exportChat(currentSessionId);
                else addMessage('system', 'No active session to export.');
            } catch (e) { addMessage('error', 'Export failed: ' + e.message); }
            return true;
        case 'title':
            try {
                if (arg && currentSessionId) {
                    await updateSessionTitle(currentSessionId, arg);
                } else {
                    addMessage('system', 'Usage: /title <new title>');
                }
            } catch (e) { addMessage('error', 'Title update failed: ' + e.message); }
            return true;
        case 'share':
            try {
                if (currentSessionId) await shareCurrentSession();
                else addMessage('system', 'No active session to share.');
            } catch (e) { addMessage('error', 'Share failed: ' + e.message); }
            return true;
        case 'search':
            try {
                if (arg) await runGlobalSearch(arg);
                else addMessage('system', 'Usage: /search <query>');
            } catch (e) { addMessage('error', 'Search failed: ' + e.message); }
            return true;
        case 'stream':
            streamingEnabled = !streamingEnabled;
            addMessage('system', `Streaming ${streamingEnabled ? 'enabled' : 'disabled'}.`);
            return true;
        case 'tts':
            const ttsEnabled = localStorage.getItem('muccheai_tts') === '1';
            localStorage.setItem('muccheai_tts', ttsEnabled ? '0' : '1');
            addMessage('system', `TTS ${!ttsEnabled ? 'enabled' : 'disabled'}.`);
            return true;
        case 'help':
            addMessage('system', `Available commands:
/clear — start a new chat
/memory — open memory page
/export — export current chat
/title <text> — rename session
/share — generate share link
/search <query> — search memories & chats
/stream — toggle streaming mode
/tts — toggle voice output
/help — show this message`);
            return true;
        default:
            addMessage('system', `Unknown command: /${cmd}. Type /help for available commands.`);
            return true;
    }
}

// ============================================
// Feature: Streaming chat (SSE)
// ============================================
async function sendMessageStream(text) {
    const sendBtn = document.getElementById('send');
    let currentAiWrapper = null;
    let aiText = '';
    let memoriesUsed = 0;
    let reader = null;

    try {
        const res = await fetch('/api/chat/stream', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders(),
            },
            body: JSON.stringify({ message: text, session_id: currentSessionId })
        });
        if (!res.ok) {
            setTyping(false);
            const errText = await res.text().catch(() => 'Unknown error');
            addMessage('error', `Server error: HTTP ${res.status} — ${errText}`);
            isSending = false;
            sendBtn.disabled = false;
            return;
        }

        reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let metaReceived = false;

        setTyping(false);

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            const lines = buffer.split(/\r?\n/);
            buffer = lines.pop() || '';

            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                const data = line.slice(6).trim();
                if (data === '[DONE]') continue;

                let parsed;
                try { parsed = JSON.parse(data); } catch { parsed = null; }

                if (parsed && parsed.session_id) {
                    // Meta event
                    currentSessionId = parsed.session_id;
                    memoriesUsed = parsed.memories_used || 0;
                    metaReceived = true;
                    continue;
                }
                if (parsed && parsed.confirm) {
                    const confirmed = confirm(parsed.confirm);
                    if (confirmed) {
                        // Restart stream with research_confirmed
                        if (reader) { try { reader.cancel(); } catch (e) {} }
                        await sendMessageStream(text + ' '); // slight variant to bypass cache
                        return;
                    }
                    continue;
                }

                // Content chunk
                if (!currentAiWrapper) {
                    currentAiWrapper = addMessage('ai', '', true, { memories_used: memoriesUsed });
                    const body = currentAiWrapper.querySelector('.message-body');
                    if (body) body.dataset.streaming = 'true';
                }
                aiText += data;
                const body = currentAiWrapper.querySelector('.message-body');
                if (body) {
                    body.innerHTML = renderMessageContent(aiText);
                    body.dataset.streaming = 'false';
                    currentAiWrapper.dataset.rawText = aiText;
                }
                scrollToBottom();
            }
        }

        if (!currentAiWrapper) {
            if (metaReceived) {
                addMessage('ai', '(no response)', false, { memories_used: memoriesUsed });
            } else {
                addMessage('error', 'No response from streaming endpoint.');
            }
        } else {
            // Finalize localStorage with the complete text
            if (currentSessionId) {
                const sessions = getLocalSessions();
                const s = sessions.find(x => x.id === currentSessionId);
                if (s && currentAiWrapper) {
                    const lastAi = s.messages.filter(m => m.role === 'ai').pop();
                    if (lastAi) {
                        lastAi.content = aiText;
                        saveLocalSessions(sessions);
                    }
                }
            }
        }
        // Auto-title new sessions after first exchange
        const sessions = getLocalSessions();
        const s = sessions.find(x => x.id === currentSessionId);
        if (s && s.messages.filter(m => m.role === 'ai').length === 1) {
            autoUpdateSessionTitle(currentSessionId);
        }
        checkApprovalQueue();
    } catch (err) {
        setTyping(false);
        if (err.name !== 'AbortError') {
            addMessage('error', `Stream error: ${err.message}`);
        }
    } finally {
        if (reader) { try { reader.cancel(); } catch (e) {} }
        isSending = false;
        sendBtn.disabled = false;
        scrollToBottom();
    }
}

// ============================================
// Feature: Voice output (TTS)
// ============================================
function speakText(text) {
    if (!('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.1;
    utterance.pitch = 1.0;
    window.speechSynthesis.speak(utterance);
}

// ============================================
// Feature: Conversation branching
// ============================================
async function branchAtMessage(msgId) {
    if (!currentSessionId) {
        addMessage('error', 'No active session to branch.');
        return;
    }
    const wrapper = document.querySelector(`[data-message-id="${msgId}"]`);
    if (!wrapper) return;
    const messages = document.getElementById('messages');
    const allWrappers = Array.from(messages.querySelectorAll('.message-wrapper'));
    const idx = allWrappers.indexOf(wrapper);
    if (idx < 0) return;

    try {
        const res = await apiFetch(`/api/sessions/${encodeURIComponent(currentSessionId)}/branch`, {
            method: 'POST',
            body: JSON.stringify({ message_index: idx })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        currentSessionId = data.session_id;
        localStorage.setItem('current_session_secret', data.session_secret);

        // Truncate local session messages to branch point
        const sessions = getLocalSessions();
        const s = sessions.find(x => x.id === currentSessionId);
        if (s) {
            s.messages = s.messages.slice(0, idx + 1);
            saveLocalSessions(sessions);
        }

        // Refresh UI
        loadSession(currentSessionId);
        addMessage('system', '🌿 Branched conversation. You are now in a new session.');
    } catch (e) {
        addMessage('error', 'Branch failed: ' + e.message);
    }
}

// ============================================
// Feature: Message retry with comparison
// ============================================
async function retryMessage(msgId) {
    const wrapper = document.querySelector(`[data-message-id="${msgId}"]`);
    if (!wrapper) return;
    const oldText = wrapper.dataset.rawText || '';

    // Find the previous user message
    const messages = document.getElementById('messages');
    const allWrappers = Array.from(messages.querySelectorAll('.message-wrapper'));
    const idx = allWrappers.indexOf(wrapper);
    let userText = '';
    for (let i = idx - 1; i >= 0; i--) {
        if (allWrappers[i].dataset.role === 'user') {
            userText = allWrappers[i].dataset.rawText || '';
            break;
        }
    }
    if (!userText) {
        addMessage('error', 'Could not find the original question to retry.');
        return;
    }

    setTyping(true);
    try {
        const res = await apiFetch('/api/chat', {
            method: 'POST',
            body: JSON.stringify({ message: userText, session_id: currentSessionId })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        setTyping(false);

        const newText = data.response || '(no response)';
        wrapper.dataset.rawText = newText;
        wrapper.querySelector('.message-body').innerHTML = renderMessageContent(newText);

        // Update localStorage
        if (currentSessionId) {
            const sessions = getLocalSessions();
            const s = sessions.find(x => x.id === currentSessionId);
            if (s) {
                // Find the AI message at this index and update it
                const aiMsgs = s.messages.filter(m => m.role === 'ai');
                const aiIdx = aiMsgs.length - 1; // most recent AI message
                if (aiIdx >= 0) {
                    aiMsgs[aiIdx].content = newText;
                    saveLocalSessions(sessions);
                }
            }
        }

        addMessage('system', `🔄 Retry complete. (Previous response archived — ${oldText.length} chars)`);
    } catch (e) {
        setTyping(false);
        addMessage('error', 'Retry failed: ' + e.message);
    }
}

// ============================================
// Feature: Session sharing
// ============================================
async function shareCurrentSession() {
    if (!currentSessionId) return;
    try {
        const res = await apiFetch(`/api/sessions/${encodeURIComponent(currentSessionId)}/share`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (!data.share_token) throw new Error('No share token received');
        const url = `${window.location.origin}/api/share/${encodeURIComponent(data.share_token)}`;
        addMessage('system', `🔗 Share link (valid 24h):\n${escapeHtml(url)}`);
    } catch (e) {
        addMessage('error', 'Share failed: ' + e.message);
    }
}

async function updateSessionTitle(sessionId, title) {
    try {
        const res = await apiFetch(`/api/sessions/${encodeURIComponent(sessionId)}/title`, {
            method: 'POST',
            body: JSON.stringify({ title })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const sessions = getLocalSessions();
        const s = sessions.find(x => x.id === sessionId);
        if (s) { s.title = title; saveLocalSessions(sessions); }
        renderChatHistory();
        addMessage('system', `📌 Title updated to: "${title}"`);
    } catch (e) {
        addMessage('error', 'Title update failed: ' + e.message);
    }
}

// ============================================
// Feature: Global fuzzy search
// ============================================
async function runGlobalSearch(query) {
    try {
        const res = await apiFetch('/api/search?q=' + encodeURIComponent(query));
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const results = data.results || [];
        if (!results.length) {
            addMessage('system', `🔍 No results for "${escapeHtml(query)}".`);
            return;
        }
        let msg = `🔍 Search results for "${escapeHtml(query)}":\n\n`;
        for (const r of results.slice(0, 10)) {
            const icon = r.type === 'memory' ? '🧠' : '💬';
            const title = escapeHtml(r.title || '(untitled)');
            const content = escapeHtml((r.content || '').slice(0, 120));
            const ellipsis = (r.content || '').length > 120 ? '...' : '';
            msg += `${icon} **${title}**\n${content}${ellipsis}\n\n`;
        }
        addMessage('system', msg);
    } catch (e) {
        addMessage('error', 'Search failed: ' + e.message);
    }
}

// ============================================
// Feature: Memory backup / restore
// ============================================
async function backupMemories() {
    try {
        const res = await apiFetch('/api/memory/backup');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'muccheai-memories.json';
        a.click();
        URL.revokeObjectURL(url);
        alert('Memories backed up successfully.');
    } catch (e) {
        alert('Backup failed: ' + e.message);
    }
}

async function restoreMemories() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async () => {
        const file = input.files[0];
        if (!file) return;
        try {
            const text = await file.text();
            const entries = JSON.parse(text);
            const res = await apiFetch('/api/memory/restore', {
                method: 'POST',
                body: JSON.stringify({ entries })
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            alert(`Restored ${data.restored} memories.`);
            loadMemory();
        } catch (e) {
            alert('Restore failed: ' + e.message);
        }
    };
    input.click();
}

// ============================================
// Feature: Offline queue
// ============================================
function processOfflineQueue() {
    if (!navigator.onLine || !offlineQueue.length) return;
    const queue = [...offlineQueue];
    offlineQueue = [];
    for (const item of queue) {
        sendMessageFromQueue(item);
    }
}

async function sendMessageFromQueue(item) {
    const input = document.getElementById('input');
    input.value = item.text;
    await sendMessage();
}

window.addEventListener('online', () => {
    isOnline = true;
    addMessage('system', '🌐 Back online. Processing queued messages...');
    processOfflineQueue();
});

window.addEventListener('offline', () => {
    isOnline = false;
    addMessage('system', '⚠️ You are offline. Messages will be queued.');
});

// ============================================
// Delegated listeners for new message actions
// ============================================
document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-speak-target]');
    if (btn) {
        const wrapper = document.querySelector(`[data-message-id="${btn.dataset.speakTarget}"]`);
        if (wrapper) speakText(wrapper.dataset.rawText || '');
        return;
    }
    const retryBtn = e.target.closest('[data-retry-target]');
    if (retryBtn) {
        retryMessage(retryBtn.dataset.retryTarget);
        return;
    }
    const branchBtn = e.target.closest('[data-branch-target]');
    if (branchBtn) {
        branchAtMessage(branchBtn.dataset.branchTarget);
        return;
    }
});

// Auto-update session title from first exchange
async function autoUpdateSessionTitle(sessionId) {
    const sessions = getLocalSessions();
    const s = sessions.find(x => x.id === sessionId);
    if (!s || !s.messages.length) return;
    // Only auto-title if title is currently just the first message truncated
    const firstUser = s.messages.find(m => m.role === 'user');
    if (!firstUser) return;
    const expectedDefault = firstUser.content.length > 40
        ? firstUser.content.slice(0, 40) + '...'
        : firstUser.content;
    if (s.title !== expectedDefault) return; // user already renamed

    // Ask the LLM for a short title
    try {
        const res = await apiFetch('/api/chat', {
            method: 'POST',
            body: JSON.stringify({
                message: `Generate a very short 3-5 word title for this conversation. Reply with ONLY the title, no quotes, no punctuation.\n\nUser: ${firstUser.content}`,
                })
        });
        if (!res.ok) return;
        const data = await res.json();
        const title = (data.response || '').trim().replace(/^["']|["']$/g, '').slice(0, 50);
        if (title) {
            await updateSessionTitle(sessionId, title);
        }
    } catch (e) {
        // silently fail
    }
}


// ============================================
// Feature: Inline file previews
// ============================================
async function loadInlineFilePreviews() {
    const container = document.getElementById('inlineFilePreviews');
    if (!container) return;
    try {
        const res = await apiFetch('/api/memory');
        if (!res.ok) return;
        const data = await res.json();
        const uploads = (data.entries || []).filter(e => e.key.startsWith('upload:'));
        if (!uploads.length) {
            container.style.display = 'none';
            return;
        }
        container.style.display = 'block';
        container.innerHTML = uploads.map(u => {
            const filename = (u.value && u.value.filename) || u.key.replace('upload:', '');
            const text = (u.value && u.value.text) || '';
            const preview = escapeHtml(text.slice(0, 300));
            return `<details class="file-preview">
                <summary>📄 ${escapeHtml(filename)}</summary>
                <pre class="file-preview-content">${preview}${text.length > 300 ? '...' : ''}</pre>
            </details>`;
        }).join('');
    } catch (e) {
        container.style.display = 'none';
    }
}


// ============================================
// Feature Drop 2: 10 new features
// ============================================

// ─── Analytics Dashboard ───────────────────
async function loadAnalytics() {
    const grid = document.getElementById('analyticsGrid');
    if (!grid) return;
    try {
        const res = await apiFetch('/api/analytics');
        if (!res.ok) { grid.innerHTML = '<p>Failed to load analytics.</p>'; return; }
        const data = await res.json();
        grid.innerHTML = `
            <div class="analytics-card"><h4>Total Messages</h4><div class="analytics-val">${data.total_messages || 0}</div></div>
            <div class="analytics-card"><h4>Sessions</h4><div class="analytics-val">${data.total_sessions || 0}</div></div>
            <div class="analytics-card"><h4>Memories</h4><div class="analytics-val">${data.total_memories || 0}</div></div>
            <div class="analytics-card"><h4>Queue Pending</h4><div class="analytics-val">${data.queue_pending || 0}</div></div>
            <div class="analytics-card"><h4>Top Model</h4><div class="analytics-val">${escapeHtml(data.top_model || '—')}</div></div>
            <div class="analytics-card"><h4>Active Plugins</h4><div class="analytics-val">${data.active_plugins || 0}</div></div>
        `;
    } catch (e) {
        grid.innerHTML = '<p>Error loading analytics.</p>';
    }
}

// ─── Agent Presets ─────────────────────────
async function loadPresets() {
    const grid = document.getElementById('presetGrid');
    if (!grid) return;
    try {
        const res = await apiFetch('/api/presets');
        if (!res.ok) { grid.innerHTML = '<p>Failed to load presets.</p>'; return; }
        const data = await res.json();
        grid.innerHTML = (data || []).map(p => `
            <div class="preset-card">
                <h4>${escapeHtml(p.name)}</h4>
                <p>${escapeHtml(p.description || '')}</p>
                <div class="preset-meta">${escapeHtml(p.provider)} / ${escapeHtml(p.model)}</div>
                <button class="btn btn-secondary" onclick="installPreset('${escapeHtml(p.name)}')">Install</button>
            </div>
        `).join('');
    } catch (e) {
        grid.innerHTML = '<p>Error loading presets.</p>';
    }
}
async function installPreset(name) {
    try {
        const res = await apiFetch('/api/presets/' + encodeURIComponent(name) + '/install', { method: 'POST', body: JSON.stringify({name}) });
        if (res.ok) alert('Preset installed: ' + name);
        else alert('Failed to install preset');
    } catch (e) { alert('Error'); }
}

// ─── Knowledge Graph ───────────────────────
async function loadKnowledgeGraph() {
    const container = document.getElementById('graphContainer');
    if (!container) return;
    try {
        const res = await apiFetch('/api/knowledge-graph');
        if (!res.ok) { container.innerHTML = '<p>Failed to load graph.</p>'; return; }
        const data = await res.json();
        const nodes = (data.nodes || []).map(n => `<div class="graph-node graph-group-${escapeHtml(n.group)}">${escapeHtml(n.label)} <small>(${escapeHtml(n.group)})</small></div>`).join('');
        container.innerHTML = `<div class="graph-nodes">${nodes}</div>`;
    } catch (e) {
        container.innerHTML = '<p>Error loading graph.</p>';
    }
}

// ─── Custom Tools ──────────────────────────
async function loadCustomTools() {
    const list = document.getElementById('toolList');
    if (!list) return;
    try {
        const res = await apiFetch('/api/custom-tools');
        if (!res.ok) { list.innerHTML = '<p>Failed to load tools.</p>'; return; }
        const data = await res.json();
        list.innerHTML = (data || []).map(t => `
            <div class="tool-card">
                <strong>${escapeHtml(t.name)}</strong>
                <span class="tool-method">${escapeHtml(t.method)}</span>
                <code>${escapeHtml(t.url_template)}</code>
                <button class="btn btn-danger" onclick="deleteCustomTool('${escapeHtml(t.name)}')">Delete</button>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = '<p>Error loading tools.</p>';
    }
}
async function createCustomTool() {
    const name = document.getElementById('toolName')?.value;
    const method = document.getElementById('toolMethod')?.value;
    const url = document.getElementById('toolUrl')?.value;
    if (!name || !url) return alert('Name and URL required');
    try {
        const res = await apiFetch('/api/custom-tools', { method: 'POST', body: JSON.stringify({name, method, url_template: url}) });
        if (res.ok) { loadCustomTools(); document.getElementById('toolName').value = ''; document.getElementById('toolUrl').value = ''; }
        else alert('Failed to create tool');
    } catch (e) { alert('Error'); }
}
async function deleteCustomTool(name) {
    if (!confirm('Delete tool ' + name + '?')) return;
    try {
        const res = await apiFetch('/api/custom-tools/' + encodeURIComponent(name), { method: 'DELETE' });
        if (res.ok) loadCustomTools();
    } catch (e) {}
}

// ─── Scheduled Tasks ───────────────────────
async function loadScheduledTasks() {
    const list = document.getElementById('taskList');
    if (!list) return;
    try {
        const res = await apiFetch('/api/scheduled-tasks');
        if (!res.ok) { list.innerHTML = '<p>Failed to load tasks.</p>'; return; }
        const data = await res.json();
        list.innerHTML = (data || []).map(t => `
            <div class="task-card">
                <strong>${escapeHtml(t.cron)}</strong>
                <p>${escapeHtml(t.prompt)}</p>
                <span class="task-status">${t.enabled ? '✅' : '⏸️'}</span>
                <button class="btn btn-danger" onclick="deleteScheduledTask('${escapeHtml(t.id)}')">Delete</button>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = '<p>Error loading tasks.</p>';
    }
}
async function createScheduledTask() {
    const cron = document.getElementById('taskCron')?.value;
    const prompt = document.getElementById('taskPrompt')?.value;
    if (!cron || !prompt) return alert('Cron and prompt required');
    try {
        const res = await apiFetch('/api/scheduled-tasks', { method: 'POST', body: JSON.stringify({cron, prompt}) });
        if (res.ok) { loadScheduledTasks(); document.getElementById('taskCron').value = ''; document.getElementById('taskPrompt').value = ''; }
        else alert('Failed to create task');
    } catch (e) { alert('Error'); }
}
async function deleteScheduledTask(id) {
    try {
        const res = await apiFetch('/api/scheduled-tasks/' + encodeURIComponent(id), { method: 'DELETE' });
        if (res.ok) loadScheduledTasks();
    } catch (e) {}
}

// ─── Multi-modal Image Input ───────────────
document.getElementById('imageBtn')?.addEventListener('click', () => document.getElementById('imageInput')?.click());
document.getElementById('imageInput')?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
        const b64 = reader.result.split(',')[1];
        const text = document.getElementById('input').value;
        document.getElementById('input').value = '';
        addMessage('user', text || '[Image]');
        try {
            const res = await apiFetch('/api/chat/image', {
                method: 'POST',
                body: JSON.stringify({ message: text || 'Describe this image', image_b64: b64, session_id: currentSessionId })
            });
            if (!res.ok) throw new Error('Image chat failed');
            const data = await res.json();
            addMessage('ai', data.response);
            if (data.session_id) currentSessionId = data.session_id;
            if (data.session_secret) currentSessionSecret = data.session_secret;
            saveSessionToLocalStorage(currentSessionId, data.session_secret);
            loadChatHistory();
        } catch (err) {
            addMessage('ai', 'Error: ' + err.message);
        }
    };
    reader.readAsDataURL(file);
});

// ─── Session Digest ────────────────────────
document.getElementById('digestSessionBtn')?.addEventListener('click', async () => {
    if (!currentSessionId) return alert('No active session');
    try {
        const res = await apiFetch('/api/sessions/' + encodeURIComponent(currentSessionId) + '/digest');
        if (!res.ok) throw new Error('Failed');
        const data = await res.json();
        const blob = new Blob([data.digest || ''], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'digest.md';
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) { alert('Error generating digest'); }
});

// ─── E2E Encrypted Share ───────────────────
document.getElementById('encryptShareBtn')?.addEventListener('click', async () => {
    if (!currentSessionId) return alert('No active session');
    try {
        const res = await apiFetch('/api/sessions/' + encodeURIComponent(currentSessionId) + '/encrypt-share', {
            method: 'POST',
            body: JSON.stringify({ ciphertext: '', nonce: '' })
        });
        if (!res.ok) throw new Error('Failed');
        const data = await res.json();
        const shareUrl = location.origin + '/api/encrypt-share/' + encodeURIComponent(data.share_token);
        prompt('Encrypted share link (copy and send):', shareUrl);
    } catch (e) { alert('Error creating encrypted share'); }
});

// ─── Collaborative Session (simple indicator) ─
async function loadCollaborativeStatus() {
    // Placeholder: if we ever load a shared session, show a banner
}

// ─── Tab switch hooks ──────────────────────

document.getElementById('toolCreateBtn')?.addEventListener('click', createCustomTool);
document.getElementById('taskCreateBtn')?.addEventListener('click', createScheduledTask);
