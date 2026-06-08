// ===== MuccheAI Web UI =====
const API = (window.location.port === '8888') ? 'http://127.0.0.1:3000' : '';
let token = localStorage.getItem('token') || '';
let csrfToken = localStorage.getItem('csrf_token') || '';
let currentTheme = localStorage.getItem('theme') || 'dark-chat';
let aiName = localStorage.getItem('aiName') || 'MuccheAI';

// ===== Theme System =====
function applyTheme(name) {
  currentTheme = name;
  localStorage.setItem('theme', name);
  let link = document.getElementById('theme-link');
  if (!link) {
    link = document.createElement('link');
    link.id = 'theme-link';
    link.rel = 'stylesheet';
    document.head.appendChild(link);
  }
  // Smooth transition: add a class that dims the body, swap, then restore
  document.body.classList.add('theme-transitioning');
  link.href = `/themes/${name}.css?v=2`;
  document.body.setAttribute('data-theme', name);
  setTimeout(() => document.body.classList.remove('theme-transitioning'), 350);
}

function showThemePicker() {
  const modal = document.getElementById('themePickerModal');
  if (modal) modal.style.display = 'flex';
}

function initTheme() {
  const saved = localStorage.getItem('theme');
  if (!saved) {
    setTimeout(showThemePicker, 500);
  } else {
    applyTheme(saved);
  }
}

// ===== Auth =====
async function login(user, pass) {
  const res = await fetch(`${API}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass })
  });
  if (!res.ok) throw new Error('Login failed');
  const data = await res.json();
  token = data.token;
  localStorage.setItem('token', token);
  await fetchCsrf();
  closeModal('apiKeyModal');
  maybeShowNameAiModal();
  loadPersonasAndAgents();
}

async function register(user, pass) {
  const res = await fetch(`${API}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass })
  });
  if (!res.ok) throw new Error('Registration failed');
  const data = await res.json();
  token = data.token;
  localStorage.setItem('token', token);
  await fetchCsrf();
  closeModal('apiKeyModal');
  maybeShowNameAiModal();
  loadPersonasAndAgents();
}

async function fetchCsrf() {
  try {
    const res = await fetch(`${API}/api/csrf`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (res.ok) {
      const data = await res.json();
      csrfToken = data.csrf_token || '';
      localStorage.setItem('csrf_token', csrfToken);
    }
  } catch (_) {}
}



function logout() {
  token = '';
  localStorage.removeItem('token');
  localStorage.removeItem('aiName');
  location.reload();
}

function maybeShowNameAiModal() {
  if (!localStorage.getItem('aiName')) {
    setTimeout(() => openModal('nameAiModal'), 400);
  }
}

// ===== Tabs =====
function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const tab = document.getElementById('tab-' + tabId);
  if (tab) tab.classList.add('active');
  const nav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
  if (nav) nav.classList.add('active');
  const title = tabId.charAt(0).toUpperCase() + tabId.slice(1);
  document.getElementById('pageTitle').textContent = title;
}

// ===== Chat =====
let currentStreamEl = null;
let streamInterval = null;

function addMessage(text, isUser) {
  const container = document.getElementById('messages');
  const welcome = container.querySelector('.welcome-message');
  if (welcome) welcome.remove();

  const div = document.createElement('div');
  div.className = 'message ' + (isUser ? 'user' : 'ai');
  // Simple markdown-ish formatting
  div.innerHTML = formatMarkdown(text);
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

let codeBlockId = 0;
const codeBlockMap = new Map();

function formatMarkdown(text) {
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.1);padding:2px 4px;border-radius:4px;font-family:monospace;font-size:0.85em;">$1</code>')
    .replace(/```([\s\S]*?)```/g, (match, code) => {
      const id = 'cb-' + (++codeBlockId);
      codeBlockMap.set(id, code.trim());
      return `<div style="position:relative;margin:8px 0;">
        <button class="btn btn-secondary copy-code-btn" data-id="${id}" style="position:absolute;top:6px;right:6px;padding:4px 10px;font-size:0.75rem;opacity:0;transition:opacity 0.2s;">Copy</button>
        <pre style="background:rgba(0,0,0,0.2);padding:12px;border-radius:8px;overflow-x:auto;font-family:monospace;font-size:0.85em;margin:0;"><code>${escapeHtml(code.trim())}</code></pre>
      </div>`;
    });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function startStream() {
  const container = document.getElementById('messages');
  const welcome = container.querySelector('.welcome-message');
  if (welcome) welcome.remove();

  if (currentStreamEl) currentStreamEl.remove();
  if (streamInterval) clearInterval(streamInterval);

  const div = document.createElement('div');
  div.className = 'message ai';
  div.innerHTML = '<span class="stream-cursor">▋</span>';
  container.appendChild(div);
  currentStreamEl = div;
  container.scrollTop = container.scrollHeight;
  return div;
}

function appendStream(text) {
  if (!currentStreamEl) return;
  const cursor = currentStreamEl.querySelector('.stream-cursor');
  if (cursor) cursor.remove();
  currentStreamEl.innerHTML = formatMarkdown(currentStreamEl.textContent + text) + '<span class="stream-cursor">▋</span>';
  const container = document.getElementById('messages');
  container.scrollTop = container.scrollHeight;
}

function endStream() {
  if (!currentStreamEl) return;
  const cursor = currentStreamEl.querySelector('.stream-cursor');
  if (cursor) cursor.remove();
  currentStreamEl = null;
  if (streamInterval) { clearInterval(streamInterval); streamInterval = null; }
}

function showTyping(show) {
  const el = document.getElementById('typingIndicator');
  if (el) el.classList.toggle('hidden', !show);
}

async function sendChat() {
  const input = document.getElementById('input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  addMessage(text, true);
  showTyping(true);

  try {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const res = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ message: text, session_id: currentSession() })
    });
    showTyping(false);
    if (!res.ok) {
      if (res.status === 403) {
        addMessage('Session expired. Please log in again.', false);
        logout();
      } else {
        addMessage('Error: ' + res.status, false);
      }
      return;
    }
    const data = await res.json();
    const response = data.response || data.message || '...';
    // Stream the response character by character for visual effect
    startStream();
    let i = 0;
    const chunkSize = 3;
    const delay = 15;
    streamInterval = setInterval(() => {
      if (i >= response.length) {
        endStream();
        return;
      }
      appendStream(response.slice(i, i + chunkSize));
      i += chunkSize;
    }, delay);
  } catch (e) {
    showTyping(false);
    addMessage('Network error. Please try again.', false);
  }
}

// Real SSE streaming chat (used when backend supports it)
async function sendChatStream() {
  const input = document.getElementById('input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  addMessage(text, true);
  showTyping(true);

  try {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const res = await fetch(`${API}/api/chat/stream`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ message: text, session_id: currentSession() })
    });
    showTyping(false);
    if (!res.ok) {
      if (res.status === 403) {
        addMessage('Session expired. Please log in again.', false);
        logout();
        return;
      }
      // Fall back to non-streaming endpoint
      sendChat();
      return;
    }
    startStream();
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data: ')) continue;
        const data = trimmed.slice(6);
        if (data === '[DONE]') { endStream(); return; }
        appendStream(data);
      }
    }
    endStream();
  } catch (e) {
    showTyping(false);
    // Fall back to non-streaming
    sendChat();
  }
}

function currentSession() {
  return localStorage.getItem('session_id') || '';
}

// ===== Data Loading =====
async function loadPersonasAndAgents() {
  try {
    const [pRes, aRes] = await Promise.all([
      fetch(`${API}/api/personas`, { headers: { 'Authorization': 'Bearer ' + token } }),
      fetch(`${API}/api/agents`, { headers: { 'Authorization': 'Bearer ' + token } })
    ]);
    if (pRes.ok) {
      const data = await pRes.json();
      const sel = document.getElementById('personaSelect');
      if (sel && data.personas) {
        sel.innerHTML = data.personas.map(p => `<option value="${p.id}">${p.emoji || ''} ${p.name}</option>`).join('');
      }
    }
    if (aRes.ok) {
      const data = await aRes.json();
      const sel = document.getElementById('agentSelect');
      if (sel && data.agents) {
        sel.innerHTML = data.agents.map(a => `<option value="${a.id}">${a.name} (${a.model})</option>`).join('');
      }
    }
  } catch (_) {}
}

// ===== Settings =====
function openSettings() { document.getElementById('settingsModal').style.display = 'flex'; }
function closeSettings() { document.getElementById('settingsModal').style.display = 'none'; }

// ===== Modals =====
function openModal(id) { document.getElementById(id).style.display = 'flex'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }

// ===== Mock Data for Demo =====
const MOCK_PERSONAS = [
  { id: 'default', name: 'Default', emoji: '🐄', desc: 'Balanced, helpful assistant.' },
  { id: 'engineer', name: 'Engineer', emoji: '⚙️', desc: 'Focused on code and architecture.' },
  { id: 'creative', name: 'Creative', emoji: '🎨', desc: 'Imaginative and artistic.' },
  { id: 'researcher', name: 'Researcher', emoji: '🔬', desc: 'Deep dives into topics.' },
  { id: 'concise', name: 'Concise', emoji: '⚡', desc: 'Short and to the point.' },
];
const MOCK_MCP = [
  { name: 'filesystem', transport: 'stdio', status: 'connected' },
  { name: 'github', transport: 'stdio', status: 'idle' },
];
const MOCK_STATUS = [
  { label: 'Backend', value: 'Online', healthy: true },
  { label: 'Ollama', value: 'Connected', healthy: true },
  { label: 'PQC Keys', value: 'Active', healthy: true },
  { label: 'Memory Rules', value: '42', healthy: true },
  { label: 'Total Tokens', value: '1.2M', healthy: true },
];
const MOCK_MEMORIES = [
  { type: 'Fact', key: 'user_name', value: 'Alice' },
  { type: 'Preference', key: 'language', value: 'English' },
  { type: 'Fact', key: 'timezone', value: 'UTC-3' },
];
const MOCK_CHAT_HISTORY = [
  { id: '1', title: 'Rust workspace setup', date: '2h ago' },
  { id: '2', title: 'Theme system design', date: '5h ago' },
  { id: '3', title: 'Argon2 params review', date: '1d ago' },
  { id: '4', title: 'MCP server integration', date: '2d ago' },
];

function renderChatHistory() {
  const list = document.getElementById('chatHistoryList');
  if (!list) return;
  list.innerHTML = MOCK_CHAT_HISTORY.map(h => `
    <a href="#" class="nav-item chat-history-item" data-session="${h.id}" style="font-size:0.8rem;padding:6px 10px;">
      <span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;">${h.title}</span>
      <span style="font-size:0.65rem;color:var(--text-dim);margin-left:4px;white-space:nowrap;">${h.date}</span>
    </a>
  `).join('');
  list.querySelectorAll('.chat-history-item').forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      localStorage.setItem('session_id', item.dataset.session);
      document.getElementById('messages').innerHTML = `<div class="message ai">Loaded session: <strong>${item.querySelector('span').textContent}</strong></div>`;
    });
  });
}

function renderPersonas() {
  const grid = document.getElementById('personaGrid');
  if (!grid) return;
  grid.innerHTML = MOCK_PERSONAS.map(p => `
    <div class="persona-card" data-id="${p.id}">
      <div class="emoji">${p.emoji}</div>
      <div class="name">${p.name}</div>
      <div class="desc">${p.desc}</div>
    </div>
  `).join('');
  grid.querySelectorAll('.persona-card').forEach(card => {
    card.addEventListener('click', () => {
      grid.querySelectorAll('.persona-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      const sel = document.getElementById('personaSelect');
      if (sel) sel.value = card.dataset.id;
    });
  });
}

function renderMcp() {
  const list = document.getElementById('mcpList');
  if (!list) return;
  list.innerHTML = MOCK_MCP.map(m => `
    <div class="mcp-item">
      <div>
        <strong>${m.name}</strong>
        <div class="meta">${m.transport} · ${m.status}</div>
      </div>
      <button class="btn btn-secondary">Test</button>
    </div>
  `).join('');
}

function renderStatus() {
  const grid = document.getElementById('statusGrid');
  if (!grid) return;
  grid.innerHTML = MOCK_STATUS.map(s => `
    <div class="status-card">
      <div class="label">${s.label}</div>
      <div class="value" style="color:${s.healthy ? '#51cf66' : '#ff6b6b'}">${s.value}</div>
    </div>
  `).join('');
  document.getElementById('ruleCount').textContent = '42';
  document.getElementById('tokenCount').textContent = '1.2M';
  document.getElementById('ollamaDot').classList.add('green');
}

function renderMemories() {
  const facts = document.getElementById('factsList');
  const prefs = document.getElementById('preferencesList');
  if (facts) facts.innerHTML = MOCK_MEMORIES.filter(m => m.type === 'Fact').map(m => `
    <div class="memory-item"><span><strong>${m.key}</strong>: ${m.value}</span><button>Delete</button></div>
  `).join('');
  if (prefs) prefs.innerHTML = MOCK_MEMORIES.filter(m => m.type === 'Preference').map(m => `
    <div class="memory-item"><span><strong>${m.key}</strong>: ${m.value}</span><button>Delete</button></div>
  `).join('');
}

// ===== Event Listeners =====
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  renderPersonas();
  renderMcp();
  renderStatus();
  renderMemories();
  renderChatHistory();

  // Update version badge and status sidebar
  async function updateStatus() {
    try {
      const res = await fetch(`${API}/api/status`, {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data.version) {
        const badge = document.getElementById('versionBadge');
        if (badge) badge.textContent = 'v' + data.version;
        const display = document.getElementById('versionDisplay');
        if (display) display.textContent = 'v' + data.version;
      }
      if (data.ollama_connected !== undefined) {
        const dot = document.getElementById('ollamaDot');
        if (dot) dot.classList.toggle('green', data.ollama_connected);
      }
      if (data.policy_rule_count !== undefined) {
        const el = document.getElementById('ruleCount');
        if (el) el.textContent = data.policy_rule_count;
      }
    } catch (_) {}
  }
  updateStatus();
  setInterval(updateStatus, 30000);

  // Login
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async e => {
      e.preventDefault();
      const user = document.getElementById('loginUser').value;
      const pass = document.getElementById('loginPass').value;
      try { await login(user, pass); }
      catch (err) {
        const el = document.getElementById('loginError');
        el.textContent = err.message;
        el.style.display = 'block';
      }
    });
  }

  // Register
  const registerBtn = document.getElementById('registerBtn');
  if (registerBtn) {
    registerBtn.addEventListener('click', async () => {
      const user = document.getElementById('loginUser').value;
      const pass = document.getElementById('loginPass').value;
      if (!user || !pass) {
        const el = document.getElementById('loginError');
        el.textContent = 'Please enter username and password';
        el.style.display = 'block';
        return;
      }
      try { await register(user, pass); }
      catch (err) {
        const el = document.getElementById('loginError');
        el.textContent = err.message;
        el.style.display = 'block';
      }
    });
  }

  // Name AI modal
  const nameAiForm = document.querySelector('#nameAiModal form');
  if (nameAiForm) {
    nameAiForm.addEventListener('submit', e => {
      e.preventDefault();
      const val = document.getElementById('aiNameInput').value.trim();
      if (val) {
        aiName = val;
        localStorage.setItem('aiName', aiName);
        document.querySelector('.welcome-message h2').textContent = '🐄 Welcome to ' + aiName;
        document.getElementById('input').placeholder = 'Message ' + aiName + '...';
      }
      closeModal('nameAiModal');
    });
  }

  if (!token) {
    openModal('apiKeyModal');
  } else {
    closeModal('apiKeyModal');
    loadPersonasAndAgents();
  }

  // Update AI name in UI
  if (aiName) {
    const welcomeH2 = document.querySelector('.welcome-message h2');
    if (welcomeH2) welcomeH2.textContent = '🐄 Welcome to ' + aiName;
    const inputEl = document.getElementById('input');
    if (inputEl) inputEl.placeholder = 'Message ' + aiName + '...';
    document.title = aiName + ' — Secure AI Agent';
  }

  // Highlight current theme in picker
  document.querySelectorAll('.theme-option').forEach(opt => {
    opt.classList.toggle('selected', opt.dataset.theme === currentTheme);
  });

  // Tabs
  document.querySelectorAll('.nav-item[data-tab]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      switchTab(el.dataset.tab);
    });
  });

  // Chat
  const sendBtn = document.getElementById('send');
  const chatInput = document.getElementById('input');
  if (sendBtn) sendBtn.addEventListener('click', sendChatStream);
  if (chatInput) {
    chatInput.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChatStream(); }
    });
  }

  // File upload (visual only)
  const uploadBtn = document.getElementById('uploadBtn');
  const fileInput = document.getElementById('fileInput');
  if (uploadBtn && fileInput) {
    uploadBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      if (file) addMessage('📎 Attached: ' + file.name, true);
      fileInput.value = '';
    });
  }

  // Image upload (visual only)
  const imageBtn = document.getElementById('imageBtn');
  const imageInput = document.getElementById('imageInput');
  if (imageBtn && imageInput) {
    imageBtn.addEventListener('click', () => imageInput.click());
    imageInput.addEventListener('change', () => {
      const file = imageInput.files[0];
      if (file) addMessage('🖼️ Image: ' + file.name, true);
      imageInput.value = '';
    });
  }

  // Voice input (visual only)
  const voiceBtn = document.getElementById('voiceBtn');
  if (voiceBtn) {
    voiceBtn.addEventListener('click', () => {
      addMessage('🎤 Voice input not available in this browser.', false);
    });
  }

  // Settings button in sidebar
  const settingsBtn = document.querySelector('.nav-item:not([data-tab])');
  if (settingsBtn) settingsBtn.addEventListener('click', e => { e.preventDefault(); openSettings(); });

  // Close modals via X buttons
  document.querySelectorAll('.modal .btn-icon, .api-key-modal .btn-icon').forEach(btn => {
    btn.addEventListener('click', () => {
      const modal = btn.closest('.modal, .api-key-modal');
      if (modal) modal.style.display = 'none';
    });
  });

  // Slide panel
  const apiPanelToggle = document.getElementById('apiPanelToggleBtn');
  const apiPanel = document.getElementById('apiPanel');
  const apiBackdrop = document.getElementById('apiPanelBackdrop');
  if (apiPanelToggle) {
    apiPanelToggle.addEventListener('click', () => {
      apiPanel.classList.toggle('open');
      apiBackdrop.classList.toggle('open');
    });
  }
  if (apiBackdrop) {
    apiBackdrop.addEventListener('click', () => {
      apiPanel.classList.remove('open');
      apiBackdrop.classList.remove('open');
    });
  }

  // Logout
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  // Dark mode / theme toggle button
  const darkModeBtn = document.getElementById('darkModeBtn');
  if (darkModeBtn) {
    darkModeBtn.addEventListener('click', () => {
      showThemePicker();
    });
  }

  // New chat
  const newChatBtn = document.getElementById('newChatBtn');
  if (newChatBtn) {
    newChatBtn.addEventListener('click', () => {
      document.getElementById('messages').innerHTML = `
        <div class="welcome-message">
          <h2>🐄 Welcome to ${aiName}</h2>
          <p>Your local, secure AI agent. Select a persona and start chatting.</p>
        </div>`;
      localStorage.removeItem('session_id');
    });
  }

  // Duress PIN toggle
  const loginPass = document.getElementById('loginPass');
  const duressSection = document.getElementById('duressPinSection');
  if (loginPass && duressSection) {
    loginPass.addEventListener('focus', () => { duressSection.style.display = 'block'; });
  }

  // Theme picker options
  document.querySelectorAll('.theme-option').forEach(opt => {
    opt.addEventListener('click', () => {
      applyTheme(opt.dataset.theme);
      document.querySelectorAll('.theme-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      const modal = document.getElementById('themePickerModal');
      if (modal) modal.style.display = 'none';
    });
  });

  // Rename AI from settings
  const renameAiBtn = document.getElementById('renameAiBtn');
  if (renameAiBtn) {
    renameAiBtn.addEventListener('click', () => {
      const val = document.getElementById('settingAiName').value.trim();
      if (val) {
        aiName = val;
        localStorage.setItem('aiName', aiName);
        document.querySelector('.welcome-message h2').textContent = '🐄 Welcome to ' + aiName;
        document.getElementById('input').placeholder = 'Message ' + aiName + '...';
      }
    });
  }

  // Change theme button in settings
  const changeThemeBtn = document.getElementById('changeThemeBtn');
  if (changeThemeBtn) {
    changeThemeBtn.addEventListener('click', () => {
      showThemePicker();
    });
  }

  // Temperature slider
  const tempSlider = document.getElementById('settingTemp');
  if (tempSlider) {
    tempSlider.addEventListener('input', e => {
      document.getElementById('tempValue').textContent = e.target.value;
    });
  }

  // Sidebar toggle for mobile
  const sidebarToggle = document.getElementById('sidebarToggleBtn');
  const sidebar = document.querySelector('.sidebar');
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }

  // Close sidebar when clicking outside on mobile
  document.addEventListener('click', e => {
    if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('open')) {
      if (!sidebar.contains(e.target) && e.target !== sidebarToggle) {
        sidebar.classList.remove('open');
      }
    }
  });

  // Research modal
  const runResearchBtn = document.getElementById('runResearchBtn');
  if (runResearchBtn) {
    runResearchBtn.addEventListener('click', async () => {
      const query = document.getElementById('researchQuery').value.trim();
      if (!query) return;
      const result = document.getElementById('researchResult');
      const loading = document.getElementById('researchLoading');
      loading.style.display = 'block';
      result.textContent = '';
      await new Promise(r => setTimeout(r, 1200));
      loading.style.display = 'none';
      result.textContent = `Research results for "${query}":\n\nBased on your chat history, you've discussed:\n• Rust programming (37%)\n• AI architecture (22%)\n• Security & cryptography (18%)\n• DevOps & deployment (13%)\n• Other topics (10%)\n\nTop collaborators: local-llm, cargo, docker.`;
    });
  }

  // Memory add form
  const memoryAddBtn = document.querySelector('#memory-subtab-memories .memory-add-form button');
  if (memoryAddBtn) {
    memoryAddBtn.addEventListener('click', e => {
      e.preventDefault();
      const type = document.getElementById('memoryTypeSelect').value;
      const key = document.getElementById('memoryKeyInput').value.trim();
      const value = document.getElementById('memoryValueInput').value.trim();
      if (!key || !value) return;
      MOCK_MEMORIES.push({ type, key, value });
      renderMemories();
      document.getElementById('memoryKeyInput').value = '';
      document.getElementById('memoryValueInput').value = '';
    });
  }

  // Memory subtabs
  const subtabMemories = document.getElementById('subtab-memories');
  const subtabQueue = document.getElementById('subtab-queue');
  if (subtabMemories && subtabQueue) {
    subtabMemories.addEventListener('click', () => {
      subtabMemories.classList.add('active');
      subtabQueue.classList.remove('active');
      document.getElementById('memory-subtab-memories').style.display = 'block';
      document.getElementById('memory-subtab-queue').style.display = 'none';
    });
    subtabQueue.addEventListener('click', () => {
      subtabQueue.classList.add('active');
      subtabMemories.classList.remove('active');
      document.getElementById('memory-subtab-memories').style.display = 'none';
      document.getElementById('memory-subtab-queue').style.display = 'block';
    });
  }

  // MCP transport toggle
  const mcpTransport = document.getElementById('mcpTransport');
  const mcpStdioFields = document.getElementById('mcpStdioFields');
  const mcpHttpFields = document.getElementById('mcpHttpFields');
  if (mcpTransport) {
    mcpTransport.addEventListener('change', e => {
      const isHttp = e.target.value === 'http';
      if (mcpStdioFields) mcpStdioFields.style.display = isHttp ? 'none' : 'block';
      if (mcpHttpFields) mcpHttpFields.style.display = isHttp ? 'block' : 'none';
    });
  }

  // MCP add button
  const mcpAddBtn = document.getElementById('mcpAddBtn');
  if (mcpAddBtn) {
    mcpAddBtn.addEventListener('click', () => {
      const name = document.getElementById('mcpName').value.trim();
      if (!name) return;
      MOCK_MCP.push({ name, transport: mcpTransport.value, status: 'idle' });
      renderMcp();
      document.getElementById('mcpName').value = '';
    });
  }

  // Global search
  const globalSearchBtn = document.getElementById('globalSearchBtn');
  if (globalSearchBtn) {
    globalSearchBtn.addEventListener('click', () => {
      const term = prompt('Search all chats:');
      if (term) addMessage('🔎 Search: ' + term, false);
    });
  }

  // Research chats button
  const researchChatsBtn = document.getElementById('researchChatsBtn');
  if (researchChatsBtn) {
    researchChatsBtn.addEventListener('click', () => openModal('researchModal'));
  }

  // Share / digest / encrypt buttons (mock)
  document.getElementById('shareSessionBtn')?.addEventListener('click', () => addMessage('🔗 Session link copied to clipboard.', false));
  document.getElementById('digestSessionBtn')?.addEventListener('click', () => addMessage('📋 Session digest generated.', false));
  document.getElementById('encryptShareBtn')?.addEventListener('click', () => addMessage('🔐 Encrypted share created.', false));

  // Copy code buttons (delegated)
  document.getElementById('messages').addEventListener('click', e => {
    const btn = e.target.closest('.copy-code-btn');
    if (!btn) return;
    const id = btn.dataset.id;
    const code = codeBlockMap.get(id);
    if (code) {
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 1500);
      }).catch(() => {
        btn.textContent = 'Failed';
        setTimeout(() => btn.textContent = 'Copy', 1500);
      });
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    // Escape closes modals
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal, .api-key-modal').forEach(m => m.style.display = 'none');
    }
    // Cmd/Ctrl + K → global search
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      const term = prompt('Search all chats:');
      if (term) addMessage('🔎 Search: ' + term, false);
    }
    // Cmd/Ctrl + N → new chat
    if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
      e.preventDefault();
      newChatBtn?.click();
    }
    // Cmd/Ctrl + , → settings
    if ((e.metaKey || e.ctrlKey) && e.key === ',') {
      e.preventDefault();
      openSettings();
    }
    // Cmd/Ctrl + Shift + P → theme picker
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'P') {
      e.preventDefault();
      showThemePicker();
    }
  });
});
