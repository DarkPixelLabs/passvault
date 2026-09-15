const state = { csrf: '', editingId: null };
const $ = (id) => document.getElementById(id);

async function refreshCsrf() {
  const response = await fetch('/api/csrf');
  const data = await response.json();
  state.csrf = data.token;
}

async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    headers['X-CSRF-TOKEN'] = state.csrf;
  }
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    showAuth('Your session expired. Please unlock the vault.');
    throw new Error('unauthorized');
  }
  return response;
}

function showAuth(message = '') {
  $('auth-view').classList.remove('hidden');
  $('vault-view').classList.add('hidden');
  $('setup-screen').classList.add('hidden');
  $('login-screen').classList.remove('hidden');
  $('login-message').textContent = message || 'Enter your master password.';
}

function showError(message) { $('auth-error').textContent = message || ''; }

async function initialize() {
  try {
    await refreshCsrf();
    const response = await fetch('/api/setup/status');
    const status = await response.json();
    if (status.configured) showAuth();
    else {
      $('setup-screen').classList.remove('hidden');
      $('login-screen').classList.add('hidden');
    }
  } catch { showError('Unable to contact PassVault.'); }
}

$('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault(); showError('');
  const password = $('setup-password').value;
  const response = await api('/api/setup', { method: 'POST', body: JSON.stringify({ masterPassword: password }) });
  const data = await response.json();
  $('setup-password').value = '';
  if (!response.ok) { showError(data.error || 'Setup failed.'); return; }
  showAuth('Vault initialized. Please unlock it.');
});

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); showError('');
  const password = $('login-password').value;
  const response = await api('/api/login', { method: 'POST', body: JSON.stringify({ masterPassword: password }) });
  const data = await response.json();
  $('login-password').value = '';
  if (!response.ok) { showError(data.error || 'Invalid master password.'); return; }
  await loadVault();
});

async function loadVault() {
  const response = await api('/api/vault');
  if (!response.ok) return;
  const entries = await response.json();
  $('auth-view').classList.add('hidden'); $('vault-view').classList.remove('hidden');
  $('entry-count').textContent = `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}`;
  const list = $('vault-list'); list.innerHTML = '';
  if (!entries.length) { list.innerHTML = '<div class="empty">Your vault is empty. Add your first credential.</div>'; return; }
  entries.forEach(renderEntry);
}

function renderEntry(entry) {
  const card = document.createElement('article'); card.className = 'entry'; card.dataset.id = entry.id;
  card.innerHTML = `<div><h2>${escapeHtml(entry.siteName)}</h2><div class="entry-meta">${escapeHtml(entry.username || '—')} ${entry.url ? '· ' + escapeHtml(entry.url) : ''}</div><div class="password-reveal hidden"></div></div><div class="actions"><button data-action="reveal">REVEAL</button><button class="ghost" data-action="edit">EDIT</button><button class="ghost" data-action="delete">DELETE</button></div>`;
  card.querySelector('[data-action="reveal"]').onclick = () => reveal(entry.id, card);
  card.querySelector('[data-action="edit"]').onclick = () => openEditor(entry);
  card.querySelector('[data-action="delete"]').onclick = () => removeEntry(entry.id);
  $('vault-list').appendChild(card);
}

async function reveal(id, card) {
  const response = await api(`/api/vault/${id}/reveal`); if (!response.ok) return;
  const data = await response.json(); const output = card.querySelector('.password-reveal');
  output.textContent = data.password; output.classList.remove('hidden');
  navigator.clipboard?.writeText(data.password).catch(() => {});
  window.setTimeout(() => { output.textContent = ''; output.classList.add('hidden'); }, 10000);
}

$('add-button').onclick = () => openEditor();
$('cancel-button').onclick = () => $('entry-dialog').close();
$('logout-button').onclick = async () => { await api('/api/logout', { method: 'POST', body: '{}' }); showAuth(); };

function openEditor(entry = null) {
  state.editingId = entry?.id || null; $('dialog-title').textContent = entry ? 'Edit entry' : 'New entry';
  $('entry-site').value = entry?.siteName || ''; $('entry-username').value = entry?.username || '';
  $('entry-url').value = entry?.url || ''; $('entry-password').value = ''; $('entry-notes').value = ''; $('entry-id').value = state.editingId || '';
  $('entry-dialog').showModal();
}

$('entry-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = { siteName: $('entry-site').value, username: $('entry-username').value, url: $('entry-url').value, password: $('entry-password').value, notes: $('entry-notes').value || null };
  const path = state.editingId ? `/api/vault/${state.editingId}` : '/api/vault';
  const response = await api(path, { method: state.editingId ? 'PUT' : 'POST', body: JSON.stringify(payload) });
  if (!response.ok) { const data = await response.json(); alert(data.error || 'Unable to save entry.'); return; }
  $('entry-dialog').close(); await loadVault();
});

async function removeEntry(id) {
  if (!confirm('Delete this vault entry?')) return;
  const response = await api(`/api/vault/${id}`, { method: 'DELETE', body: '{}' });
  if (response.ok) await loadVault();
}

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char])); }

initialize();
