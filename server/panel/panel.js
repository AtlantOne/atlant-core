'use strict';
let key = '', subscriptions = [], editing = '', editingRevision = '';
const $ = id => document.getElementById(id);
const status = value => { $('status').textContent = value; };
const bytes = value => { const n = Number(value || 0); return n >= 1073741824 ? (n / 1073741824).toFixed(2) + ' ГиБ' : (n / 1048576).toFixed(1) + ' МиБ'; };
function quotaGiB(value) {
  const text = String(value).trim().replace(',', '.');
  if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(text)) throw new Error('Введите лимит, например 0,1; 0 — безлимит');
  const n = Number(text);
  if (!Number.isFinite(n) || n < 0 || n > 1e8 || (n > 0 && n * 1073741824 < 1)) throw new Error('Лимит вне диапазона');
  return n;
}
async function api(path, method = 'GET', body) {
  if (!key) throw new Error('Введите API-ключ');
  const response = await fetch('/api/' + path, { method, headers: { 'X-API-Key': key, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
  if (!response.ok) throw new Error('Запрос не выполнен: HTTP ' + response.status);
  return response.json();
}
function button(label, action) { const b = document.createElement('button'); b.textContent = label; b.onclick = () => Promise.resolve().then(action).catch(e => status(e.message)); return b; }
function node(value = {}) {
  const row = $('node-template').content.firstElementChild.cloneNode(true);
  const format = document.createElement('option');
  format.value = '7'; format.textContent = '7 · прямой QUIC REALITY';
  format.selected = true;
  row.querySelector('[data-field="wire_version"]').appendChild(format);
  for (const input of row.querySelectorAll('[data-field]')) if (value[input.dataset.field] !== undefined) input.value = value[input.dataset.field];
  row.querySelector('.remove-node').onclick = () => row.remove(); $('nodes').appendChild(row);
}
function resetSub() { editing = ''; $('sub-global-quota').disabled = false; $('sub-global-quota').checked = false; $('sub-quota').value = '0'; $('subscription-heading').textContent = 'Новая подписка'; $('sub-title').value = ''; $('sub-expire').value = ''; $('sub-support').value = ''; $('sub-announcement').value = ''; $('sub-enabled').checked = true; $('secret-link').value = ''; $('nodes').replaceChildren(); node(); }
function edit(s) {
  editingRevision = s.revision;
  $('sub-global-quota').checked = s.total_limit !== undefined; $('sub-global-quota').disabled = s.total_limit !== undefined;
  $('sub-quota').value = String((s.total_limit || 0) / 1073741824);
  editing = s.id; $('subscription-heading').textContent = 'Редактирование подписки'; $('sub-user').value = s.user; $('sub-title').value = s.title; $('sub-hours').value = s.update_hours;
  $('sub-expire').value = s.expires_at ? new Date(s.expires_at * 1000).toISOString().slice(0, 10) : ''; $('sub-support').value = s.support_url || ''; $('sub-announcement').value = s.announcement || ''; $('sub-enabled').checked = s.enabled;
  $('nodes').replaceChildren(); s.nodes.forEach(node); $('secret-link').value = '';
}
async function refresh() {
  const [users, subs, config] = await Promise.all([api('users'), api('subscriptions'), api('subscription-service')]);
  const list = Array.isArray(users) ? users : users.users || [];
  $('users').replaceChildren(); $('sub-user').replaceChildren(); $('user-count').textContent = list.length + ' записей';
  for (const u of list) {
    const row = document.createElement('tr');
    for (const text of [u.name, u.enabled ? 'Включён' : 'Отключён', bytes(u.up_bytes), bytes(u.down_bytes), u.total_limit ? bytes(u.total_limit) : 'Безлимит', u.expires_at ? new Date(u.expires_at * 1000).toLocaleDateString() : 'Без срока']) { const cell = document.createElement('td'); cell.textContent = text; row.appendChild(cell); }
    if (u.total_limit > 0) {
      const used = Number(u.up_bytes || 0) + Number(u.down_bytes || 0);
      const meter = document.createElement('progress'); meter.max = u.total_limit; meter.value = Math.min(u.total_limit, used);
      meter.setAttribute('aria-label', 'Использованный трафик');
      row.children[4].appendChild(document.createElement('br')); row.children[4].appendChild(meter);
      const remaining = document.createElement('div'); remaining.textContent = 'Осталось ' + bytes(Math.max(0, u.total_limit - used)); row.children[4].appendChild(remaining);
    }
    const actions = document.createElement('td'); actions.appendChild(button(u.enabled ? 'Отключить' : 'Включить', async () => { await api('user/' + (u.enabled ? 'disable' : 'enable') + '?name=' + encodeURIComponent(u.name), 'POST'); await refresh(); }));
    if (u.subscription_id) { row.children[4].textContent = 'Общая квота подписки'; row.children[4].title = u.subscription_id; }
    else actions.appendChild(button('Лимит', async () => { const value = prompt('Лимит в ГиБ (например 0,1; 0 — безлимит)', String((u.total_limit || 0) / 1073741824)); if (value === null) return; await api('user/update', 'POST', {name: u.name, limit_gb: quotaGiB(value)}); await refresh(); }));
    row.appendChild(actions); $('users').appendChild(row);
    const option = document.createElement('option'); option.value = u.name; option.textContent = u.name; $('sub-user').appendChild(option);
  }
  subscriptions = subs; $('subscriptions').replaceChildren();
  for (const s of subs) {
    const card = document.createElement('div'); card.className = 'subscription-card'; const title = document.createElement('strong'); title.textContent = s.title + ' · ' + s.user + ' · ' + s.nodes.length + ' узлов' + (s.enabled ? '' : ' · отключена'); card.appendChild(title); card.appendChild(document.createElement('br'));
    if (s.global_quota) {
      const q = s.global_quota, used = q.upload + q.download;
      const label = document.createElement('p'); label.textContent = 'Общий трафик: ' + bytes(used) + ' / ' + (q.total_limit ? bytes(q.total_limit) : 'безлимит') + '. Зарезервировано VDS: ' + bytes(q.reserved); card.appendChild(label);
      if (q.total_limit > 0) { const meter = document.createElement('progress'); meter.max = q.total_limit; meter.value = Math.min(used, q.total_limit); meter.setAttribute('aria-label', 'Общий трафик подписки'); card.appendChild(meter); }
    }
    card.appendChild(button('Изменить', () => edit(s)));
    card.appendChild(button('Перевыпустить ссылку', async () => { if (!confirm('Старая ссылка перестанет работать. Продолжить?')) return; const result = await api('subscriptions', 'PUT', { ...s, rotate: true }); $('secret-link').value = result.url; status('Новая ссылка выдана. Сохраните её в безопасном месте.'); }));
    card.appendChild(button('Удалить', async () => { if (!confirm('Удалить подписку?')) return; await api('subscriptions?id=' + encodeURIComponent(s.id), 'DELETE'); await refresh(); })); $('subscriptions').appendChild(card);
  }
  $('tls-enabled').checked = !!config.enabled; $('tls-listen').value = config.listen || ':8443'; $('tls-public').value = config.public_url || '';
  const t = config.tls || {}; for (const [id, field] of [['tls-mode','mode'],['tls-host','host'],['tls-cert','cert_file'],['tls-key','key_file'],['tls-cache','cache_dir'],['tls-email','email']]) if (t[field]) $(id).value = t[field];
  const certificate = config.status || {};
  $('certificate-status').textContent = (certificate.listening ? 'HTTPS запущен. ' : 'HTTPS не запущен. ') + (certificate.not_after ? 'Сертификат до ' + new Date(certificate.not_after).toLocaleString() + '. ' : '') + (certificate.renew_before ? 'Продление до ' + new Date(certificate.renew_before).toLocaleString() + '. ' : '') + (certificate.error || '');
  $('tls-terms').checked = !!t.accept_terms; $('tls-staging').checked = !!t.staging; status('Данные обновлены');
}
$('connect').onclick = () => { key = $('api-key').value.trim(); $('api-key').value = ''; refresh().catch(e => status(e.message)); };
$('logout').onclick = () => { key = ''; subscriptions = []; $('quota-secret').value = ''; $('users').replaceChildren(); $('subscriptions').replaceChildren(); $('sub-user').replaceChildren(); resetSub(); status('Вы вышли. API-ключ удалён из памяти страницы.'); };
$('reload').onclick = () => refresh().catch(e => status(e.message));
$('create-user').onclick = () => Promise.resolve().then(() => api('user/add', 'POST', { name: $('user-name').value.trim(), limit_gb: quotaGiB($('user-limit').value), expire_days: Number($('user-days').value), enabled: true })).then(refresh).catch(e => status(e.message));
$('add-node').onclick = () => node(); $('new-sub').onclick = () => { resetSub(); $('sub-global-quota').disabled = false; $('sub-global-quota').checked = false; $('sub-quota').value = '0'; };
$('save-sub').onclick = async () => {
  try {
    const nodes = [...$('nodes').children].map(row => Object.fromEntries([...row.querySelectorAll('[data-field]')].map(input => [input.dataset.field, input.dataset.field === 'wire_version' ? Number(input.value) : input.value.trim()])));
    const input = { id: editing, user: $('sub-user').value, title: $('sub-title').value.trim(), enabled: $('sub-enabled').checked, expires_at: $('sub-expire').value ? Math.floor(new Date($('sub-expire').value + 'T23:59:59').getTime() / 1000) : 0, update_hours: Number($('sub-hours').value), support_url: $('sub-support').value.trim(), announcement: $('sub-announcement').value, nodes };
    if (editing) input.revision = editingRevision;
    if ($('sub-global-quota').checked) { input.total_limit = Math.floor(quotaGiB($('sub-quota').value) * 1073741824); if (!Number.isSafeInteger(input.total_limit)) throw new Error('Лимит слишком велик для точного ввода через панель'); }
    const result = await api('subscriptions', editing ? 'PUT' : 'POST', input); editing = result.subscription.id; editingRevision = result.subscription.revision; if (result.url) $('secret-link').value = result.url; await refresh(); status('Подписка сохранена. Новую ссылку скопируйте из поля ниже.');
  } catch (e) { status(e.message); }
};
$('quota-enroll').onclick = () => api('quota/nodes', 'POST', { id: $('quota-node').value.trim(), enabled: true, subscriptions: $('quota-subs').value.split(',').map(s => s.trim()).filter(Boolean) }).then(r => { $('quota-secret').value = r.token; status('Ключ выдан один раз. Сохраните его на соответствующем VDS.'); }).catch(e => status(e.message));
$('quota-disable').onclick = () => api('quota/nodes', 'DELETE', { id: $('quota-node').value.trim(), subscriptions: [], enabled: false }).then(() => { $('quota-secret').value = ''; status('Узел отключён; действующие разрешения истекут не позднее чем через 6 секунд.'); }).catch(e => status(e.message));
$('quota-bind').onclick = () => api('quota/bindings', 'PUT', { user: $('quota-user').value.trim(), subscription: $('quota-bind-sub').value.trim() }).then(() => status('Учётная запись привязана к подписке.')).catch(e => status(e.message));
$('save-tls').onclick = async () => {
  try {
    await api('subscription-service', 'POST', { enabled: $('tls-enabled').checked, listen: $('tls-listen').value.trim(), public_url: $('tls-public').value.trim(), tls: { mode: $('tls-mode').value, host: $('tls-host').value.trim(), cert_file: $('tls-cert').value.trim(), key_file: $('tls-key').value.trim(), cache_dir: $('tls-cache').value.trim(), email: $('tls-email').value.trim(), accept_terms: $('tls-terms').checked, staging: $('tls-staging').checked, challenge_listen: ':80' } });
    status('Настройки записаны. Для изменения слушателя нужен штатный перезапуск сервера. VPN на другой порт не переключался.');
  } catch (e) { status(e.message); }
};
resetSub();
