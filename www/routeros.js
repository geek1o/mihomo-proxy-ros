/* Automatic Mode augments the preserved ENV editor; no CLI is interpreted. */
(() => {
  let state, token = null, pendingChanges = {}, watchedJob = null;
  const el = id => document.getElementById(id);
  const show = value => { el('ros-output').textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); };
  async function api(action, values = {}) {
    const response = await fetch('/cgi-bin/routeros', action ? {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action, csrf: state?.csrf, ...values})
    } : {cache: 'no-store'});
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || 'Ошибка RouterOS API');
    return data;
  }
  function changes() {
    document.querySelectorAll('#envForm input[name], #envForm textarea[name], #envForm select[name]').forEach(field => {
      if (!isSecretHidden(field)) rememberField(field);
    });
    const out = {};
    for (const name of currentCommandNames()) {
      const value = Store.get(envKey(name)) || '';
      const original = Store.get(originalKey(name)) || '';
      if (commandFor(name, original, value, originalWasPresent(name))) out[name] = value;
    }
    return out;
  }
  function network() {
    return {profile: el('ros-profile').value, container_ip: el('ros-container-ip').value.trim(),
      lan_list: el('ros-lan').value.trim(), client_subnet: el('ros-clients').value.trim(), dns_capture: el('ros-dns').checked};
  }
  async function refresh(fill = false) {
    state = await api();
    el('ros-status').textContent = (state.has_password ? 'RouterOS подключён' : 'RouterOS не подключён') +
      ' · ' + (state.job.status || 'ожидание') + (state.transaction.status ? ' · ' + state.transaction.status : '');
    if (fill) {
      for (const key of ['url', 'username', 'ca_pem']) el('ros-' + key).value = state.connection[key] || '';
      const net = state.network || {};
      el('ros-profile').value = net.profile || 'existing';
      el('ros-container-ip').value = net.container_ip || '';
      el('ros-lan').value = net.lan_list || 'LAN';
      el('ros-clients').value = net.client_subnet || '';
      el('ros-dns').checked = !!net.dns_capture;
    }
    if (state.job.id === watchedJob && !['queued','validating','applying','restarting','recovering'].includes(state.job.status)) {
      watchedJob = null;
      show({operation:state.job,transaction:state.transaction});
      if (state.job.status === 'succeeded') {
        // Rebase draft on successful apply. A full worker restart also updates the
        // server ENV snapshot; hot reload is rebased without restarting httpd.
        for (const [name,value] of Object.entries(pendingChanges)) {
          Store.set(originalKey(name),value);
          Store.set(originalPresentKey(name),value ? '1' : '0');
        }
        pendingChanges = {}; draftSaveDebounced();
        if (typeof refreshAllBadges === 'function') refreshAllBadges();
      }
    }
    return state;
  }
  async function run(fn) {
    try { await fn(); } catch (error) { show(error.message); }
  }
  function mount() {
    const panel = document.createElement('section');
    panel.id = 'routeros-integration'; panel.className = 'ros-panel';
    panel.innerHTML = `
      <details id="ros-details"><summary>RouterOS · <span id="ros-status">подключение…</span></summary>
      <p>Automatic Mode применяет настройки через HTTPS. Manual Mode сохраняет существующий генератор CLI.</p>
      <label>Режим <select id="ros-mode"><option value="automatic">Automatic Mode</option><option value="manual">Manual Mode</option></select></label>
      <div class="ros-grid">
        <label>RouterOS HTTPS URL<input id="ros-url" placeholder="https://router.example:443" autocomplete="off"></label>
        <label>API-пользователь<input id="ros-username" autocomplete="off"></label>
        <label>API-пароль<input id="ros-password" type="password" autocomplete="new-password" placeholder="Пусто — сохранить текущий"></label>
        <label>CA PEM<textarea id="ros-ca_pem" rows="3" placeholder="Пусто — системные доверенные CA"></textarea></label>
      </div>
      <button type="button" id="ros-connect">Проверить соединение и права</button>
      <details><summary>Маршрутизация и DNS</summary><div class="ros-grid">
        <label>Профиль<select id="ros-profile"><option value="existing">Существующая маршрутизация: DNS и списки</option><option value="selective">Создать selective routing IPv4</option><option value="disabled">Удалить управляемые сетевые объекты</option></select></label>
        <label>IP контейнера<input id="ros-container-ip" placeholder="172.18.0.5"></label>
        <label>LAN interface list<input id="ros-lan" value="LAN"></label>
        <label>Подсеть тестовых клиентов<input id="ros-clients" placeholder="192.168.88.100/32"></label>
        <label><input id="ros-dns" type="checkbox"> Перехватывать TCP/UDP DNS выбранных клиентов</label>
      </div><p>Профиль IPv4 не блокирует IPv6 и клиентский DoH. Перед включением проверьте сеть и preview. Новые правила сохраняют политику доступа для новых соединений.</p></details>
      <div class="ros-actions">
        <button type="button" id="ros-preview">Показать изменения</button>
        <button type="button" class="primary" id="ros-apply" disabled>Сохранить и применить</button>
        <button type="button" id="ros-recover">Восстановить предыдущие настройки</button>
        <button type="button" id="ros-log">Журнал операций</button>
      </div><pre id="ros-output" role="status" aria-live="polite"></pre></details>`;
    const main = document.querySelector('main'); if (!main) return;
    main.appendChild(panel);
    const top = document.createElement('button'); top.type = 'button'; top.className = 'primary';
    top.textContent = 'Сохранить и применить';
    top.onclick = () => { el('ros-details').open = true; panel.scrollIntoView({behavior:'smooth'}); el('ros-preview').click(); };
    document.querySelector('.header-actions, .page-actions, header .actions, .top-actions')?.appendChild(top);
    el('ros-mode').onchange = () => {
      const manual = el('ros-mode').value === 'manual';
      el('ros-apply').disabled = manual || !token;
      if (manual) generateCommands();
    };
    panel.addEventListener('input', () => { token = null; el('ros-apply').disabled = true; });
    // ENV changes elsewhere also invalidate the reviewed browser plan.
    document.getElementById('envForm')?.addEventListener('input', () => {token=null; el('ros-apply').disabled=true;});
    el('ros-connect').onclick = () => run(async () => {
      const data = await api('connect', {connection:{url:el('ros-url').value.trim(),username:el('ros-username').value.trim(),
        password:el('ros-password').value,ca_pem:el('ros-ca_pem').value.trim()}});
      el('ros-password').value=''; token=null; show(data.capabilities); await refresh();
    });
    el('ros-preview').onclick = () => run(async () => {
      if (el('ros-mode').value === 'manual') { generateCommands(); return; }
      pendingChanges=changes(); token=null;
      const data = await api('preview',{changes:pendingChanges, network:network(),restart_files:typeof LiveFiles !== 'undefined' && LiveFiles.changes().length > 0});
      token=data.token; show(data); el('ros-apply').disabled=false;
    });
    el('ros-apply').onclick = () => run(async () => {
      if (!token) throw new Error('Сначала проверьте preview');
      const data=await api('apply',{token}); watchedJob=data.job.id; token=null;
      el('ros-apply').disabled=true; show('Операция сохранена. Статус восстановится после перезапуска прокси.');
      await refresh();
    });
    el('ros-recover').onclick = () => run(async () => {
      if (!window.confirm('Восстановить объекты последней операции и предыдущую конфигурацию прокси?')) return;
      const data=await api('recover'); watchedJob=data.job.id; await refresh();
    });
    el('ros-log').onclick = () => run(async () => { await refresh(); show(state.history); });
    run(() => refresh(true));
    setInterval(() => { if (watchedJob) run(() => refresh()); },3000);
  }
  document.addEventListener('DOMContentLoaded',mount);
})();
