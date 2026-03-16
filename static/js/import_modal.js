(function (global) {
  const DEFAULT_TEXTS = {
    previewSummary: '预览结果如下，请确认后导入：',
    parseError: '解析失败，请检查格式',
    applyError: '导入失败，请稍后再试',
  };

  function defaultSummary(summary, state) {
    if (!summary) {
      return DEFAULT_TEXTS.previewSummary;
    }
    const base = `共 ${summary.total} 条，预计新增 ${summary.new} 条，跳过 ${summary.existing} 条重复。`;
    if (state.targetLabel && state.targetSpace !== 'personal') {
      return `${base}（导入到 ${state.targetLabel}）`;
    }
    return base;
  }

  function getCsrfToken() {
    if (global.appGetCsrfToken) {
      return global.appGetCsrfToken();
    }
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function setButtonLoading(button, loading, label) {
    if (global.appSetButtonLoading) {
      global.appSetButtonLoading(button, loading, { label: label || '' });
      return;
    }
    if (!button) {
      return;
    }
    if (loading) {
      button.disabled = true;
      if (!button.dataset.originalLabel) {
        button.dataset.originalLabel = button.innerHTML;
      }
      const text = label || button.dataset.originalLabel || '';
      button.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>${text}`;
    } else {
      button.disabled = false;
      if (button.dataset.originalLabel) {
        button.innerHTML = button.dataset.originalLabel;
        delete button.dataset.originalLabel;
      }
    }
  }

  function init(options) {
    const config = Object.assign(
      {
        modalId: 'importModal',
        previewUrl: '',
        applyUrl: '',
        defaultSpace: 'personal',
        summaryFormatter: defaultSummary,
      },
      options || {}
    );

    const modalEl = document.getElementById(config.modalId);
    if (!modalEl) {
      console.warn('[TotpImportModal] 未找到导入模态框元素');
      return null;
    }
    if (modalEl.dataset.importModalInitialized === '1') {
      return modalEl.__totpImportModal || null;
    }

    const importModeRadios = modalEl.querySelectorAll('input[name="importMode"]');
    const importManualPanel = document.getElementById('importManualPanel');
    const importManualText = document.getElementById('importManualText');
    const importFilePanel = document.getElementById('importFilePanel');
    const importFileInput = document.getElementById('importFileInput');
    const importSpaceSelect = document.getElementById('importSpaceSelect');
    const importAssetField = document.getElementById('importAssetField');
    const importAssetSelect = document.getElementById('importAssetSelect');
    const importAssetUrlTemplate = document.getElementById('teamAssetOptionsUrlForImport');
    const importPreviewBtn = document.getElementById('importPreviewBtn');
    const importApplyBtn = document.getElementById('importApplyBtn');
    const importErrorAlert = document.getElementById('importErrorAlert');
    const importWarningAlert = document.getElementById('importWarningAlert');
    const importWarningList = document.getElementById('importWarningList');
    const importPreviewWrapper = document.getElementById('importPreviewWrapper');
    const importPreviewBody = document.getElementById('importPreviewBody');
    const importPreviewSummary = document.getElementById('importPreviewSummary');

    const state = {
      payload: null,
      targetSpace: null,
      targetLabel: '',
      targetAssetId: '',
    };

    function getAvailableSpaceValues() {
      if (!importSpaceSelect) {
        return [];
      }
      return Array.from(importSpaceSelect.options).map((option) => option.value);
    }

    function resolveDefaultSpace() {
      const values = getAvailableSpaceValues();
      const desired = config.defaultSpace || 'personal';
      if (values.includes(desired)) {
        return desired;
      }
      if (values.includes('personal')) {
        return 'personal';
      }
      return values[0] || desired || 'personal';
    }

    function setSpaceValue(value) {
      const fallback = resolveDefaultSpace();
      const target = value || fallback;
      if (!importSpaceSelect) {
        state.targetSpace = target || 'personal';
        return state.targetSpace;
      }
      const values = getAvailableSpaceValues();
      const effective = values.includes(target) ? target : fallback;
      importSpaceSelect.value = effective;
      state.targetSpace = importSpaceSelect.value || effective || 'personal';
      return state.targetSpace;
    }

    function getCurrentSpace() {
      if (!importSpaceSelect) {
        return state.targetSpace || resolveDefaultSpace();
      }
      const value = importSpaceSelect.value;
      if (value) {
        return value;
      }
      return resolveDefaultSpace();
    }

    setSpaceValue(config.defaultSpace || 'personal');

    function parseTeamId(space) {
      if (!space || typeof space !== 'string') {
        return '';
      }
      if (!space.startsWith('team:')) {
        return '';
      }
      return space.slice(5).trim();
    }

    function buildAssetUrl(teamId) {
      const template = importAssetUrlTemplate?.value || '';
      if (!template) {
        return '';
      }
      return template.replace('/0/', `/${teamId}/`);
    }

    function setAssetOptions(items) {
      if (!importAssetSelect) {
        return;
      }
      importAssetSelect.replaceChildren();
      const emptyOption = document.createElement('option');
      emptyOption.value = '';
      emptyOption.textContent = '未归属';
      importAssetSelect.appendChild(emptyOption);
      (items || []).forEach((item) => {
        const opt = document.createElement('option');
        opt.value = String(item.id);
        opt.textContent = item.name;
        importAssetSelect.appendChild(opt);
      });
    }

    function refreshAssetField() {
      const currentSpace = getCurrentSpace();
      const teamId = parseTeamId(currentSpace);
      const isTeam = Boolean(teamId);
      if (importAssetField) {
        importAssetField.classList.toggle('d-none', !isTeam);
      }
      if (!isTeam) {
        state.targetAssetId = '';
        if (importAssetSelect) {
          importAssetSelect.value = '';
        }
        setAssetOptions([]);
        return;
      }
      const url = buildAssetUrl(teamId);
      if (!url) {
        return;
      }
      fetch(url, { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
        .then((resp) => resp.json())
        .then((data) => {
          if (!data || !data.ok) {
            return;
          }
          setAssetOptions(data.assets || []);
          if (importAssetSelect && state.targetAssetId) {
            importAssetSelect.value = state.targetAssetId;
          }
        })
        .catch(() => {});
    }

    function currentImportMode() {
      const active = Array.from(importModeRadios).find((radio) => radio.checked);
      return active ? active.value : 'manual';
    }

    function hideImportFeedback() {
      importErrorAlert?.classList.add('d-none');
      if (importWarningAlert && importWarningList) {
        importWarningAlert.classList.add('d-none');
        importWarningList.replaceChildren();
      }
    }

    function showImportError(message) {
      if (global.appNotify) {
        global.appNotify({ alertEl: importErrorAlert, variant: 'danger', message: message || DEFAULT_TEXTS.parseError });
        return;
      }
      if (!importErrorAlert) {
        return;
      }
      importErrorAlert.textContent = message;
      importErrorAlert.classList.toggle('d-none', !message);
    }

    function focusImportInput(mode) {
      if (mode === 'file') {
        importFileInput?.focus({ preventScroll: true });
        return;
      }
      importManualText?.focus({ preventScroll: true });
    }

    function showImportWarnings(warnings) {
      if (!importWarningAlert || !importWarningList) {
        return;
      }
      importWarningList.replaceChildren();
      if (warnings && warnings.length) {
        warnings.forEach((text) => {
          const li = document.createElement('li');
          li.textContent = text;
          importWarningList.appendChild(li);
        });
        importWarningAlert.classList.remove('d-none');
      } else {
        importWarningAlert.classList.add('d-none');
      }
    }

    function setImportMode(mode) {
      if (mode === 'file') {
        importManualPanel?.classList.add('d-none');
        importFilePanel?.classList.remove('d-none');
      } else {
        importManualPanel?.classList.remove('d-none');
        importFilePanel?.classList.add('d-none');
      }
      hideImportFeedback();
      state.payload = null;
      importPreviewWrapper?.classList.add('d-none');
      if (importApplyBtn) {
        importApplyBtn.classList.add('d-none');
        importApplyBtn.disabled = true;
        delete importApplyBtn.dataset.originalLabel;
        importApplyBtn.innerHTML = '确认导入';
      }
      setButtonLoading(importPreviewBtn, false);
    }

    function resetModal() {
      state.payload = null;
      state.targetLabel = '';
      state.targetAssetId = '';
      setSpaceValue(config.defaultSpace || 'personal');
      if (importAssetSelect) {
        importAssetSelect.value = '';
      }
      refreshAssetField();
      if (importManualText) {
        importManualText.value = '';
      }
      if (importFileInput) {
        importFileInput.value = '';
      }
      hideImportFeedback();
      importPreviewWrapper?.classList.add('d-none');
      importPreviewBody?.replaceChildren();
      if (importPreviewSummary) {
        importPreviewSummary.textContent = DEFAULT_TEXTS.previewSummary;
      }
      if (importApplyBtn) {
        importApplyBtn.classList.add('d-none');
        importApplyBtn.disabled = true;
      }
      setButtonLoading(importPreviewBtn, false);
      if (importModeRadios.length) {
        importModeRadios.forEach((radio) => {
          radio.checked = radio.value === 'manual';
        });
        setImportMode('manual');
      }
    }

    function renderImportPreview(entries, summary) {
      if (!importPreviewWrapper || !importPreviewBody) {
        return;
      }
      importPreviewBody.replaceChildren();
      entries.forEach((entry) => {
        const tr = document.createElement('tr');
        const nameTd = document.createElement('td');
        nameTd.textContent = entry.name || '—';

        const groupTd = document.createElement('td');
        groupTd.textContent = entry.group || '—';

        const sourceTd = document.createElement('td');
        sourceTd.textContent = entry.source || '—';

        const statusTd = document.createElement('td');
        statusTd.className = 'text-nowrap';
        const badge = document.createElement('span');
        badge.className = entry.exists ? 'badge text-bg-secondary' : 'badge text-bg-success';
        badge.textContent = entry.exists ? '已存在' : '新建';
        statusTd.appendChild(badge);

        const secretTd = document.createElement('td');
        secretTd.className = 'text-nowrap';
        const code = document.createElement('code');
        code.textContent = entry.secret_preview || '';
        secretTd.appendChild(code);

        tr.appendChild(nameTd);
        tr.appendChild(groupTd);
        tr.appendChild(sourceTd);
        tr.appendChild(statusTd);
        tr.appendChild(secretTd);
        importPreviewBody.appendChild(tr);
      });
      if (importPreviewSummary) {
        importPreviewSummary.textContent = config.summaryFormatter(summary, state);
      }
      importPreviewWrapper.classList.remove('d-none');
    }

    function handleSpaceChange() {
      state.targetSpace = setSpaceValue(importSpaceSelect?.value);
      state.targetLabel = '';
      state.payload = null;
      state.targetAssetId = '';
      if (importAssetSelect) {
        importAssetSelect.value = '';
      }
      refreshAssetField();
      importPreviewWrapper?.classList.add('d-none');
      if (importPreviewSummary) {
        importPreviewSummary.textContent = DEFAULT_TEXTS.previewSummary;
      }
      if (importApplyBtn) {
        importApplyBtn.classList.add('d-none');
        importApplyBtn.disabled = true;
      }
      hideImportFeedback();
    }

    function submitPreview() {
      hideImportFeedback();
      importPreviewWrapper?.classList.add('d-none');
      state.payload = null;
      const mode = currentImportMode();
      const formData = new FormData();
      formData.append('mode', mode);
      const currentSpace = getCurrentSpace();
      formData.append('space', currentSpace);
      const teamId = parseTeamId(currentSpace);
      if (teamId && importAssetSelect) {
        formData.append('asset_id', (importAssetSelect.value || '').trim());
      }
      if (mode === 'file') {
        const file = importFileInput?.files?.[0];
        if (!file) {
          showImportError('请选择要导入的文件');
          focusImportInput(mode);
          return;
        }
        formData.append('file', file);
      } else {
        const value = importManualText?.value.trim() || '';
        if (!value) {
          showImportError('请粘贴待导入的内容');
          focusImportInput(mode);
          return;
        }
        formData.append('manual_text', value);
      }

      setButtonLoading(importPreviewBtn, true, '解析中...');

      fetch(config.previewUrl, {
        method: 'POST',
        headers: {
          'X-CSRFToken': getCsrfToken(),
        },
        body: formData,
        credentials: 'same-origin',
      })
        .then(async (resp) => {
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok || !data.ok) {
            const message = (data.errors && data.errors[0]) || data.error || DEFAULT_TEXTS.parseError;
            throw new Error(message);
          }
          state.payload = data.entries.map((entry) => ({
            name: entry.name,
            group: entry.group,
            secret: entry.secret,
            source: entry.source,
          }));
          state.targetSpace = setSpaceValue(data.space || currentSpace);
          state.targetLabel = data.target_label || (state.targetSpace === 'personal' ? '个人空间' : '');
          state.targetAssetId = (data.asset_id || '').toString();
          if (importAssetSelect) {
            importAssetSelect.value = state.targetAssetId;
          }
          refreshAssetField();
          renderImportPreview(data.entries, data.summary);
          showImportWarnings(data.warnings || []);
          if (importApplyBtn) {
            importApplyBtn.classList.remove('d-none');
            importApplyBtn.disabled = false;
          }
          if (typeof config.onPreviewSuccess === 'function') {
            config.onPreviewSuccess(data);
          }
        })
        .catch((err) => {
          showImportError(err.message || DEFAULT_TEXTS.parseError);
        })
        .finally(() => {
          setButtonLoading(importPreviewBtn, false);
        });
    }

    function submitApply() {
      if (!state.payload || !state.payload.length) {
        showImportError('请先完成预览');
        return;
      }
      setButtonLoading(importApplyBtn, true, '导入中...');
      fetch(config.applyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ space: state.targetSpace, asset_id: state.targetAssetId || '', entries: state.payload }),
        credentials: 'same-origin',
      })
        .then(async (resp) => {
          const data = await resp.json().catch(() => ({}));
          if (data && data.error === 'reauth_required' && data.redirect) {
            window.location.href = data.redirect;
            return;
          }
          if (!resp.ok || !data.ok) {
            const message = data.error || DEFAULT_TEXTS.applyError;
            throw new Error(message);
          }
          if (typeof config.onApplySuccess === 'function') {
            config.onApplySuccess(data);
            return;
          }
          if (data.redirect) {
            window.location.href = data.redirect;
          } else {
            window.location.reload();
          }
        })
        .catch((err) => {
          showImportError(err.message || DEFAULT_TEXTS.applyError);
          setButtonLoading(importApplyBtn, false);
        });
    }

    if (importModeRadios.length) {
      importModeRadios.forEach((radio) => {
        radio.addEventListener('change', () => setImportMode(radio.value));
      });
      setImportMode(currentImportMode());
    }

    refreshAssetField();
    importSpaceSelect?.addEventListener('change', handleSpaceChange);
    importPreviewBtn?.addEventListener('click', submitPreview);
    importApplyBtn?.addEventListener('click', submitApply);
    modalEl.addEventListener('hidden.bs.modal', resetModal);

    modalEl.dataset.importModalInitialized = '1';
    const api = { reset: resetModal };
    modalEl.__totpImportModal = api;
    return api;
  }

  global.TotpImportModal = Object.assign(global.TotpImportModal || {}, { init });
})(window);
