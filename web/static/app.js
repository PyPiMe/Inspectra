// Inspectra 前端辅助：为 fetch 自动附带 CSRF token
function __t(key, fallback) {
  const d = window.__I18N || {};
  return (key in d) ? d[key] : (fallback !== undefined ? fallback : key);
}
window.inspectra = {
  csrf() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  },
};

// 通用批量选择：行复选框(.row-cb) + [data-batch-all] + [data-batch-bar] + 隐藏表单。
// Generic batch selection: row checkboxes + select-all + bar + hidden form.
function initBatch() {
  const rows = [...document.querySelectorAll('input.row-cb')];
  const bar = document.querySelector('[data-batch-bar]');
  if (!rows.length || !bar) return;
  const all = document.querySelector('[data-batch-all]');
  const cnt = bar.querySelector('[data-batch-count]');
  const checked = () => rows.filter((c) => c.checked);
  const refresh = () => {
    const n = checked().length;
    if (cnt) cnt.textContent = n;
    bar.classList.toggle('d-none', n === 0);
  };
  if (all) all.addEventListener('change', () => { rows.forEach((c) => { c.checked = all.checked; }); refresh(); });
  rows.forEach((c) => c.addEventListener('change', refresh));
  const clr = bar.querySelector('[data-batch-clear]');
  if (clr) clr.addEventListener('click', () => { rows.forEach((c) => { c.checked = false; }); if (all) all.checked = false; refresh(); });
  const del = bar.querySelector('[data-batch-delete]');
  if (del) del.addEventListener('click', () => {
    const sel = checked();
    if (!sel.length) return;
    if (!confirm((del.dataset.confirm || '').replace('{n}', sel.length))) return;
    const form = document.getElementById(del.dataset.form);
    if (!form) return;
    form.querySelectorAll('input[name="ids"]').forEach((x) => x.remove());
    sel.forEach((c) => { const i = document.createElement('input'); i.type = 'hidden'; i.name = 'ids'; i.value = c.value; form.appendChild(i); });
    form.submit();
  });
  refresh();
}

// 复制文本到剪贴板（兼容非安全上下文），btn 可选用于“已复制”反馈
function copyText(text, btn) {
  const done = () => {
    if (!btn) return;
    const old = btn.textContent;
    btn.textContent = __t('js.copied', '已复制');
    setTimeout(() => { btn.textContent = old; }, 1000);
  };
  const fallback = () => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(fallback);
  } else {
    fallback();
  }
}

// 下载文本为文件
function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// 折叠/展开长内容（pre 或 div）
function toggleFold(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('folded');
  if (btn) btn.textContent = el.classList.contains('folded') ? __t('js.expand', '展开') : __t('js.collapse', '折叠');
}


// HTML 转义
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// JSON 语法高亮（对 .json-view 内的纯文本做转义着色）
function highlightJson() {
  document.querySelectorAll('pre.json-view').forEach((pre) => {
    if (pre.dataset.hl) return;
    const text = pre.textContent;
    const esc = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    pre.innerHTML = esc.replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?)/g,
      (m) => {
        let cls = 'j-num';
        if (/^"/.test(m)) cls = /:$/.test(m) ? 'j-key' : 'j-str';
        else if (/true|false/.test(m)) cls = 'j-bool';
        else if (/null/.test(m)) cls = 'j-null';
        return `<span class="${cls}">${m}</span>`;
      }
    );
    pre.dataset.hl = '1';
  });
}
document.addEventListener('DOMContentLoaded', highlightJson);

// 脚本复选框面板：搜索 / 全选 / 清空 / 已选计数
function initScriptPickers(root) {
  (root || document).querySelectorAll('.script-picker').forEach((p) => {
    if (p.dataset.init) return;
    p.dataset.init = '1';
    const list = p.querySelector('.sp-list');
    const search = p.querySelector('.sp-search');
    const count = p.querySelector('.sp-count');
    const update = () => {
      const n = p.querySelectorAll('input[type=checkbox]:checked').length;
      if (count) count.textContent = __t('js.selected_prefix', '已选 ') + n;
    };
    const filter = () => {
      const q = (search.value || '').toLowerCase();
      p.querySelectorAll('.sp-item').forEach((it) => {
        const hidden = it.dataset.relevant === '0';
        it.style.display = (!hidden && (!q || it.dataset.name.includes(q))) ? '' : 'none';
      });
    };
    if (search) search.addEventListener('input', filter);
    const all = p.querySelector('.sp-all');
    if (all) all.addEventListener('click', () => {
      p.querySelectorAll('.sp-item').forEach((it) => {
        if (it.style.display !== 'none') it.querySelector('input').checked = true;
      });
      update();
    });
    const none = p.querySelector('.sp-none');
    if (none) none.addEventListener('click', () => {
      p.querySelectorAll('input[type=checkbox]').forEach((cb) => { cb.checked = false; });
      update();
    });
    // 标签条：单击=全选该标签脚本，再点=取消该标签脚本（一次性批量动作）
    p.querySelectorAll('.sp-tag').forEach((chip) => {
      chip.addEventListener('click', () => {
        const tg = chip.dataset.tag || '';
        const items = [...p.querySelectorAll('.sp-item')].filter(
          (it) => (it.dataset.tags || '').split(',').includes(tg)
        );
        const allChecked = items.length > 0 && items.every((it) => it.querySelector('input').checked);
        items.forEach((it) => { it.querySelector('input').checked = !allChecked; });
        update();
      });
    });
    // 仅看已选（支持初始启用：data-only-selected="1"）
    const only = p.querySelector('.sp-onlysel');
    let onlySel = false;
    const applyOnly = () => {
      if (only) only.classList.toggle('active', onlySel);
      p.querySelectorAll('.sp-item').forEach((it) => {
        const hidden = it.dataset.relevant === '0';
        const checked = it.querySelector('input').checked;
        it.style.display = (!hidden && (!onlySel || checked)) ? '' : 'none';
      });
    };
    if (only) only.addEventListener('click', () => { onlySel = !onlySel; applyOnly(); });
    if (p.dataset.onlySelected === '1') { onlySel = true; applyOnly(); }
    if (list) list.addEventListener('change', update);
    p.spRefresh = () => { filter(); update(); };
    update();
  });
}
document.addEventListener('DOMContentLoaded', () => initScriptPickers());
document.addEventListener('shown.bs.modal', () => initScriptPickers());

// 标签覆盖编辑器：默认键值行，可切换高级 JSON；同步隐藏的 labels_json 输入
function initLabelEditors(root) {
  (root || document).querySelectorAll('.label-editor').forEach((ed) => {
    if (ed.dataset.init) return;
    ed.dataset.init = '1';
    const hidden = ed.querySelector('.le-hidden');
    const rows = ed.querySelector('.le-rows');
    const json = ed.querySelector('.le-json');
    const addBtn = ed.querySelector('.le-add');
    const toggle = ed.querySelector('.le-toggle');
    if (!hidden || !rows || !json || !addBtn || !toggle) return;
    let obj = {};
    try { obj = JSON.parse(hidden.value || '{}') || {}; } catch (e) { obj = {}; }
    if (typeof obj !== 'object' || Array.isArray(obj)) obj = {};

    const rowHtml = (k, v) => (
      '<div class="input-group input-group-sm mb-1 le-row">' +
      '<input class="form-control le-k" placeholder="' + __t('server_detail.label_key', '键') + '" value="' + escapeHtml(k) + '">' +
      '<span class="input-group-text">=</span>' +
      '<input class="form-control le-v" placeholder="' + __t('server_detail.label_value', '值') + '" value="' + escapeHtml(v) + '">' +
      '<button type="button" class="btn btn-outline-danger le-del">&times;</button>' +
      '</div>'
    );
    const readRows = () => {
      const out = {};
      rows.querySelectorAll('.le-row').forEach((r) => {
        const k = (r.querySelector('.le-k').value || '').trim();
        const v = r.querySelector('.le-v').value;
        if (k) out[k] = v;
      });
      return out;
    };
    const sync = () => {
      hidden.value = JSON.stringify(obj);
      json.value = JSON.stringify(obj, null, 2);
    };
    const renderRows = () => {
      rows.innerHTML = '';
      Object.keys(obj).forEach((k) => rows.insertAdjacentHTML('beforeend', rowHtml(k, obj[k])));
      sync();
    };
    rows.addEventListener('input', () => { obj = readRows(); sync(); });
    rows.addEventListener('click', (e) => {
      const del = e.target.closest('.le-del');
      if (!del) return;
      del.closest('.le-row').remove();
      obj = readRows(); sync();
    });
    addBtn.addEventListener('click', () => {
      rows.insertAdjacentHTML('beforeend', rowHtml('', ''));
      const last = rows.querySelector('.le-row:last-child .le-k');
      if (last) last.focus();
    });
    toggle.addEventListener('click', () => {
      const nowSimple = json.classList.toggle('d-none');
      if (nowSimple) {
        rows.classList.remove('d-none');
        addBtn.classList.remove('d-none');
        try {
          obj = JSON.parse(json.value || '{}') || {};
          if (typeof obj !== 'object' || Array.isArray(obj)) obj = {};
        } catch (e) { /* keep last valid */ }
        renderRows();
        toggle.textContent = __t('server_detail.label_advanced', '高级（JSON）');
      } else {
        rows.classList.add('d-none');
        addBtn.classList.add('d-none');
        json.value = JSON.stringify(obj, null, 2);
        toggle.textContent = __t('server_detail.label_simple', '简易模式');
      }
    });
    json.addEventListener('input', () => {
      try {
        obj = JSON.parse(json.value || '{}') || {};
        if (typeof obj !== 'object' || Array.isArray(obj)) obj = {};
        hidden.value = json.value;
      } catch (e) { /* invalid JSON, wait */ }
    });
    renderRows();
  });
}
document.addEventListener('DOMContentLoaded', () => { initLabelEditors(); initBatch(); });
document.addEventListener('shown.bs.modal', () => initLabelEditors());
