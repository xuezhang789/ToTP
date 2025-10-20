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
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function setButtonLoading(button, loading, label) {
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
      if (!importErrorAlert) {
        return;
      }
      importErrorAlert.textContent = message;
      importErrorAlert.classList.toggle('d-none', !message);
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
      setSpaceValue(config.defaultSpace || 'personal');
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
        const status = entry.exists
          ? '<span class="badge text-bg-secondary">已存在</span>'
          : '<span class="badge text-bg-success">新建</span>';
        tr.innerHTML = `
          <td>${entry.name || '—'}</td>
          <td>${entry.group || '—'}</td>
          <td>${entry.source || '—'}</td>
          <td class="text-nowrap">${status}</td>
          <td class="text-nowrap"><code>${entry.secret_preview || ''}</code></td>
        `;
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
      if (mode === 'file') {
        const file = importFileInput?.files?.[0];
        if (!file) {
          showImportError('请选择要导入的文件');
          return;
        }
        formData.append('file', file);
      } else {
        const value = importManualText?.value.trim() || '';
        if (!value) {
          showImportError('请粘贴待导入的内容');
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
        body: JSON.stringify({ space: state.targetSpace, entries: state.payload }),
        credentials: 'same-origin',
      })
        .then(async (resp) => {
          const data = await resp.json().catch(() => ({}));
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
