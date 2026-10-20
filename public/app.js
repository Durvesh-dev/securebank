// SecureBank client. All output uses textContent (never innerHTML) to prevent XSS.
// Client-side checks are for usability only; the server re-validates everything.
'use strict';
const $ = (id) => document.getElementById(id);
let csrf = '';

async function api(path, method = 'GET', data) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: data ? JSON.stringify(data) : undefined,
  });
  const json = await res.json().catch(() => ({ error: 'Unexpected server response.' }));
  if (res.status === 401 && path !== '/api/login') showLogin();
  if (!res.ok) throw new Error(json.error || 'Request failed.');
  return json;
}

const inr = (n) => n.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

function cell(tr, text, cls) { const td = document.createElement('td'); td.textContent = text; if (cls) td.className = cls; tr.append(td); }

function showLogin() {
  $('loginView').hidden = false; $('customerView').hidden = true; $('adminView').hidden = true; $('session').hidden = true;
}

function showSession(user) {
  $('loginView').hidden = true; $('session').hidden = false;
  $('who').textContent = user.name; $('role').textContent = user.role;
  if (user.role === 'admin') { $('adminView').hidden = false; loadAdmin(); }
  else { $('customerView').hidden = false; loadAccount(); }
}

async function loadAccount() {
  const { user, transactions } = await api('/api/me');
  $('acc').textContent = user.accountFull;
  $('balance').textContent = '₹ ' + inr(user.balance);
  const rows = transactions.map((t) => {
    const tr = document.createElement('tr');
    cell(tr, new Date(t.date).toLocaleDateString('en-IN'));
    cell(tr, t.desc);
    cell(tr, (t.amount < 0 ? '−' : '+') + inr(Math.abs(t.amount)), 'num');
    return tr;
  });
  $('tx').replaceChildren(...rows);
}

async function loadAdmin() {
  const users = await api('/api/admin/users');
  $('users').replaceChildren(...users.map((u) => {
    const tr = document.createElement('tr');
    cell(tr, u.username); cell(tr, u.role); cell(tr, u.account || '—'); cell(tr, u.locked ? 'Yes' : 'No'); cell(tr, u.hashPrefix);
    return tr;
  }));
  const { integrity, entries } = await api('/api/admin/audit');
  $('integrity').textContent = integrity.ok ? `chain intact · ${integrity.entries} entries` : `TAMPERED at line ${integrity.brokenAt}`;
  $('audit').replaceChildren(...entries.map((e) => {
    const tr = document.createElement('tr');
    cell(tr, new Date(e.time).toLocaleString('en-IN')); cell(tr, e.level, 'lvl-' + e.level); cell(tr, e.event); cell(tr, e.user); cell(tr, e.ip);
    return tr;
  }));
}

$('loginForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('loginMsg').textContent = '';
  const username = $('username').value.trim().toLowerCase();
  const password = $('password').value;
  if (!/^[a-z0-9_]{3,20}$/.test(username) || password.length < 8) {
    $('loginMsg').textContent = 'Enter a valid username and password.'; return;
  }
  try {
    const r = await api('/api/login', 'POST', { username, password });
    csrf = r.csrf; $('password').value = '';
    showSession(r.user);
  } catch (e) { $('loginMsg').textContent = e.message; $('password').value = ''; }
});

$('transferForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const m = $('transferMsg'); m.className = 'msg';
  const data = {
    toAccount: $('toAccount').value.trim(),
    ifsc: $('ifsc').value.trim().toUpperCase(),
    amount: $('amount').value.trim(),
    remark: $('remark').value.trim(),
  };
  try {
    const r = await api('/api/transfer', 'POST', data);
    m.className = 'msg ok'; m.textContent = `Transfer successful. New balance ₹ ${inr(r.balance)}`;
    ev.target.reset(); loadAccount();
  } catch (e) { m.className = 'msg err'; m.textContent = e.message; }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', 'POST'); } catch (_) { /* session may already be gone */ }
  location.reload();
});
$('refreshAudit').addEventListener('click', () => loadAdmin().catch(() => {}));

(async function init() {
  try {
    csrf = (await api('/api/csrf')).token;
    const { user } = await api('/api/me');
    showSession(user);
  } catch (_) { showLogin(); }
})();
