// ===== MuccheAI Web UI =====
const API = (window.location.port === '8888') ? 'http://127.0.0.1:3000' : '';
let token = localStorage.getItem('token') || '';
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
  closeModal('apiKeyModal');
  maybeShowNameAiModal();
  loadPersonasAndAgents();
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
function addMessage(text, isUser) {
  const container = document.getElementById('messages');
  const welcome = container.querySelector('.welcome-message');
  if (welcome) welcome.remove();

  const div = document.createElement('div');
  div.className = 'message ' + (isUser ? 'user' : 'ai');
  // Simple markdown-ish formatting
  div.innerHTML = escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.1);padding:2px 4px;border-radius:4px;font-family:monospace;font-size:0.85em;">$1</code>')
    .replace(/```([\s\S]*?)```/g, '<pre style="background:rgba(0,0,0,0.2);padding:12px;border-radius:8px;overflow-x:auto;font-family:monospace;font-size:0.85em;margin:8px 0;"><code>$1</code></pre>');
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
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
    const res = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ message: text, session_id: currentSession() })
    });
    showTyping(false);
    if (!res.ok) {
      addMessage('Error: ' + res.status, false);
      return;
    }
    const data = await res.json();
    addMessage(data.response || data.message || '...', false);
  } catch (e) {
    showTyping(false);
    addMessage('Network error. Please try again.', false);
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

// ===== Event Listeners =====
document.addEventListener('DOMContentLoaded', () => {
  initTheme();

  // Update version badge
  fetch(`${API}/api/status`).then(r => r.ok ? r.json() : null).then(data => {
    if (data && data.version) {
      const badge = document.getElementById('versionBadge');
      if (badge) badge.textContent = 'v' + data.version;
      const display = document.getElementById('versionDisplay');
      if (display) display.textContent = 'v' + data.version;
    }
  }).catch(() => {});

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
  if (sendBtn) sendBtn.addEventListener('click', sendChat);
  if (chatInput) {
    chatInput.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
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
});
