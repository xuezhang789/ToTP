(() => {
  const config = window.TotpListConfig || {};

  const spaceForm = document.getElementById('spaceFilterForm');
  const spaceInput = document.getElementById('spaceFilterInput');
  const spaceOptions = document.querySelectorAll('.space-option');
  if (spaceForm && spaceInput && spaceOptions.length) {
    spaceOptions.forEach((option) => {
      option.addEventListener('click', () => {
        const { value } = option.dataset;
        if (!value || value === spaceInput.value) {
          return;
        }
        spaceInput.value = value;
        spaceForm.submit();
      });
    });
  }

  const tbody = document.getElementById('tbody');
  if (!tbody) {
    return;
  }

  const countdownEl = document.getElementById('countdown');
  const importPreviewUrl = config.importPreviewUrl || '';
  const importApplyUrl = config.importApplyUrl || '';
  const tokensUrl = config.tokensUrl || '';
  const refreshStatusEl = document.getElementById('refreshStatus');
  const manualRefreshBtn = document.getElementById('manualRefreshBtn');

  const state = new Map();
  let cycleRemaining = 30;
  let refreshTimer = null;
  let pendingRequest = null;
  let isPaused = document.hidden;
  let isAutoRefreshDisabled = false;
  let manualRefreshOriginalLabel = manualRefreshBtn ? manualRefreshBtn.innerHTML : '';

  const form = document.getElementById('searchForm');
  const qInput = document.getElementById('q');
  const groupSelect = document.getElementById('group');
  const assetSelect = document.getElementById('asset');
  const clearBtn = document.getElementById('clearBtn');
  const searchBtn = document.getElementById('searchBtn');
  const spinner = document.getElementById('searchSpinner');
  const renameModalEl = document.getElementById('renameModal');
  const renameForm = document.getElementById('renameForm');
  const renameEntryIdInput = document.getElementById('renameEntryId');
  const renameNameInput = document.getElementById('renameNameInput');
  const renameAlert = document.getElementById('renameAlert');
  const renameSubmitBtn = document.getElementById('renameSubmitBtn');
  const renameSpinner = document.getElementById('renameSpinner');
  let renameModalInstance = null;
  let renameTargetRow = null;
  let renameSubmitUrl = '';

  function focusElement(element, { select = false } = {}) {
    if (!element) {
      return false;
    }
    if (window.appFocusElement) {
      return window.appFocusElement(element, { select });
    }
    try {
      element.focus();
      if (select && typeof element.select === 'function') {
        element.select();
      }
      return true;
    } catch (error) {
      return false;
    }
  }

  function inlineAlert(alertEl, variant, message) {
    if (window.appInlineAlert) {
      window.appInlineAlert(alertEl, variant, message);
      return;
    }
    if (!alertEl) {
      return;
    }
    const text = message == null ? '' : String(message);
    alertEl.textContent = text;
    alertEl.classList.toggle('d-none', !text);
  }

  function notify(alertEl, variant, message) {
    if (window.appNotify) {
      window.appNotify({ alertEl, variant, message });
      return;
    }
    inlineAlert(alertEl, variant, message);
    if ((!alertEl || alertEl.classList.contains('d-none')) && window.appToast) {
      window.appToast(variant || 'danger', message);
    }
  }

  function initRows() {
    const currentIds = new Set();
    tbody.querySelectorAll('tr[data-id]').forEach((tr) => {
      const id = Number(tr.dataset.id);
      if (!Number.isFinite(id)) {
        return;
      }
      currentIds.add(id);
      const existing = state.get(id);
      if (existing) {
        existing.tr = tr;
        existing.codeEl = tr.querySelector('.code-text');
        existing.copyBtn = tr.querySelector('.copy-btn');
        existing.progressEl = tr.querySelector('.progress-bar');
        existing.remainEl = tr.querySelector('.remain');
        existing.remainMobileEl = tr.querySelector('.remain-mobile');
        existing.period = Number(tr.dataset.period) || existing.period || 30;
        return;
      }
      state.set(id, {
        tr,
        codeEl: tr.querySelector('.code-text'),
        copyBtn: tr.querySelector('.copy-btn'),
        progressEl: tr.querySelector('.progress-bar'),
        remainEl: tr.querySelector('.remain'),
        remainSuffixEl: tr.querySelector('.entry-expiry-meta span:last-child'),
        remainMobileEl: tr.querySelector('.remain-mobile'),
        hintDesktopEl: tr.querySelector('.entry-code-hint .d-none.d-md-inline'),
        period: Number(tr.dataset.period) || 30,
        lastCode: null,
        lastRemain: null,
      });
    });
    Array.from(state.keys()).forEach((id) => {
      if (!currentIds.has(id)) {
        state.delete(id);
      }
    });
  }

  function setCountdown(value) {
    cycleRemaining = Math.max(0, value);
    if (countdownEl) {
      countdownEl.textContent = cycleRemaining;
    }
  }

  function updateRefreshStatus(text) {
    if (refreshStatusEl) {
      refreshStatusEl.textContent = text;
    }
  }

  function setRefreshStatusState(state) {
    if (!refreshStatusEl) {
      return;
    }
    refreshStatusEl.dataset.state = state;
    refreshStatusEl.classList.remove('bg-light', 'text-muted', 'bg-danger', 'text-white', 'bg-success');
    if (state === 'error') {
      refreshStatusEl.classList.add('bg-danger', 'text-white');
      refreshStatusEl.setAttribute('aria-label', '刷新失败，点击重试');
      refreshStatusEl.setAttribute('title', '刷新失败，点击重试');
      return;
    }
    refreshStatusEl.classList.add('bg-light', 'text-muted');
    refreshStatusEl.removeAttribute('title');
    refreshStatusEl.setAttribute('aria-label', '自动刷新状态');
  }

  function stopTicker() {
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  function startTicker() {
    if (refreshTimer || isPaused || isAutoRefreshDisabled) {
      return;
    }
    refreshTimer = setInterval(() => {
      if (cycleRemaining <= 1) {
        refreshTokens();
        return;
      }
      setCountdown(Math.max(0, cycleRemaining - 1));
      state.forEach((row) => {
        const currentRemain = Number.isFinite(row.lastRemain) ? row.lastRemain : cycleRemaining;
        const nextRemain = currentRemain > 0 ? currentRemain - 1 : 0;
        renderRow(row, row.lastCode, nextRemain, row.period);
      });
    }, 1000);
  }

  function pauseAutoRefresh() {
    if (isPaused) {
      return;
    }
    isPaused = true;
    stopTicker();
    updateRefreshStatus('自动刷新已暂停（切回页面继续）');
  }

  function resumeAutoRefresh({ refresh = true } = {}) {
    if (!isPaused) {
      if (!refreshTimer) {
        startTicker();
      }
      return;
    }
    isPaused = false;
    if (!isAutoRefreshDisabled) {
      setRefreshStatusState('ok');
      updateRefreshStatus('自动刷新中');
    }
    if (refresh) {
      refreshTokens().finally(() => startTicker());
    } else {
      startTicker();
    }
  }

  function setManualLoading(flag) {
    if (!manualRefreshBtn) {
      return;
    }
    if (window.appSetButtonLoading) {
      window.appSetButtonLoading(manualRefreshBtn, flag, { label: '刷新中' });
      return;
    }
    if (!manualRefreshOriginalLabel) {
      manualRefreshOriginalLabel = manualRefreshBtn.innerHTML;
    }
    manualRefreshBtn.disabled = flag;
    if (flag) {
      manualRefreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>刷新中';
    } else {
      manualRefreshBtn.innerHTML = manualRefreshOriginalLabel;
    }
  }

  function setRowUnavailable(row, message = '解密失败') {
    if (row.tr) {
      row.tr.dataset.tokenState = 'unavailable';
    }
    if (row.codeEl) {
      row.codeEl.textContent = message;
      row.codeEl.dataset.code = '';
      row.codeEl.classList.remove('text-bg-dark');
      row.codeEl.classList.add('text-bg-danger');
      row.codeEl.removeAttribute('role');
      row.codeEl.removeAttribute('tabindex');
      row.codeEl.setAttribute('aria-label', message);
    }
    if (row.copyBtn) {
      row.copyBtn.dataset.code = '';
      row.copyBtn.disabled = true;
      row.copyBtn.classList.remove('btn-outline-primary', 'btn-success', 'btn-danger');
      row.copyBtn.classList.add('btn-outline-secondary');
      row.copyBtn.setAttribute('aria-label', `${message}，无法复制`);
      row.copyBtn.setAttribute('title', '当前密钥不可用');
    }
    if (row.remainEl) {
      row.remainEl.textContent = '不可用';
    }
    if (row.remainSuffixEl) {
      row.remainSuffixEl.textContent = '';
    }
    if (row.remainMobileEl) {
      row.remainMobileEl.textContent = '不可用';
    }
    if (row.hintDesktopEl) {
      row.hintDesktopEl.textContent = '当前密钥暂不可用';
    }
    if (row.progressEl) {
      row.progressEl.style.width = '0%';
    }
    const progress = row.tr ? row.tr.querySelector('[role="progressbar"]') : null;
    if (progress) {
      progress.setAttribute('aria-valuenow', '0');
    }
    row.lastCode = null;
    row.lastRemain = null;
  }

  function clearRowUnavailable(row) {
    if (row.tr && row.tr.dataset.tokenState === 'unavailable') {
      delete row.tr.dataset.tokenState;
    }
    if (row.codeEl) {
      row.codeEl.classList.remove('text-bg-danger');
      row.codeEl.classList.add('text-bg-dark');
      row.codeEl.setAttribute('role', 'button');
      row.codeEl.setAttribute('tabindex', '0');
      row.codeEl.setAttribute('aria-label', '点击复制验证码');
    }
    if (row.copyBtn) {
      row.copyBtn.disabled = false;
      row.copyBtn.classList.remove('btn-outline-secondary');
      row.copyBtn.classList.add('btn-outline-primary');
      row.copyBtn.setAttribute('aria-label', '复制验证码');
      row.copyBtn.setAttribute('title', '复制');
    }
    if (row.remainSuffixEl) {
      row.remainSuffixEl.textContent = '后刷新';
    }
    if (row.hintDesktopEl) {
      row.hintDesktopEl.textContent = '点击验证码即可复制';
    }
  }

  function renderRow(row, code, remain, period) {
    clearRowUnavailable(row);
    if (code && row.codeEl && row.codeEl.textContent !== code) {
      row.codeEl.textContent = code;
    }
    if (row.copyBtn && code && row.copyBtn.dataset.code !== code) {
      row.copyBtn.dataset.code = code;
    }
    if (row.codeEl && code && row.codeEl.dataset.code !== code) {
      row.codeEl.dataset.code = code;
    }
    if (row.remainEl && Number.isFinite(remain) && row.remainEl.textContent !== `${remain}s`) {
      row.remainEl.textContent = `${remain}s`;
    }
    if (row.remainMobileEl && Number.isFinite(remain) && row.remainMobileEl.textContent !== `${remain}s`) {
      row.remainMobileEl.textContent = `${remain}s`;
    }
    if (code) {
      row.lastCode = code;
    }
    if (Number.isFinite(remain)) {
      row.lastRemain = remain;
    }
    if (row.progressEl) {
      const safePeriod = period > 0 ? period : 30;
      const pct = Math.min(100, Math.max(0, Math.round(((safePeriod - remain) / safePeriod) * 100)));
      const nextWidth = `${pct}%`;
      if (row.progressEl.style.width !== nextWidth) {
        row.progressEl.style.width = nextWidth;
      }
      const progress = row.tr ? row.tr.querySelector('[role="progressbar"]') : null;
      if (progress) {
        progress.setAttribute('aria-valuenow', String(pct));
      }
    }
  }

  function setRenameLoading(flag) {
    if (!renameSubmitBtn) {
      return;
    }
    if (window.appSetButtonLoading) {
      window.appSetButtonLoading(renameSubmitBtn, flag, { label: '保存中' });
      return;
    }
    renameSubmitBtn.disabled = flag;
    if (renameSpinner) {
      renameSpinner.classList.toggle('d-none', !flag);
    }
  }

  function resetRenameModal() {
    renameTargetRow = null;
    renameSubmitUrl = '';
    if (renameForm) {
      renameForm.reset();
    }
    inlineAlert(renameAlert, 'danger', '');
    setRenameLoading(false);
  }

  function showRenameError(message) {
    notify(renameAlert, 'danger', message || '保存失败，请稍后再试');
  }

  async function refreshTokens() {
    if (pendingRequest) {
      return pendingRequest;
    }
    initRows();
    const ids = Array.from(state.keys()).filter((id) => Number.isFinite(id) && id > 0);
    if (!ids.length) {
      setCountdown(30);
      return Promise.resolve();
    }

    const params = new URLSearchParams();
    params.set('ids', ids.join(','));
    const url = `${tokensUrl}?${params.toString()}`;

    pendingRequest = fetch(url, {
      headers: { 'X-Requested-With': 'fetch' },
      cache: 'no-store',
    })
      .then(async (resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.json();
      })
      .then((data) => {
        isAutoRefreshDisabled = false;
        setRefreshStatusState('ok');
        updateRefreshStatus(isPaused ? '自动刷新已暂停（切回页面继续）' : '自动刷新中');
        const serverRemaining = Number.isFinite(Number(data.remaining))
          ? Number(data.remaining)
          : 30;
        setCountdown(serverRemaining);
        const items = new Map((data.items || []).map((item) => [Number(item.id), item]));
        state.forEach((row, id) => {
          const payload = items.get(id);
          if (!payload) {
            return;
          }
          if (payload.error) {
            setRowUnavailable(row, payload.error === 'unavailable' ? '解密失败' : '暂不可用');
            return;
          }
          const period = Number(payload.period) || row.period;
          row.period = period;
          const rowRemaining = Number(payload.remaining);
          const remainValue = Number.isFinite(rowRemaining) ? rowRemaining : serverRemaining;
          renderRow(row, payload.code, remainValue, period);
        });
      })
      .catch((err) => {
        console.error('Refresh tokens failed:', err);
        isAutoRefreshDisabled = true;
        stopTicker();
        setRefreshStatusState('error');
        updateRefreshStatus('刷新失败，点击重试');
        if (window.appToast) {
          window.appToast('danger', '验证码刷新失败，可点击“刷新失败”状态重试。');
        }
        if (window.appAnnounce) {
          window.appAnnounce('验证码刷新失败');
        }
      })
      .finally(() => {
        pendingRequest = null;
      });
    return pendingRequest;
  }

  async function bootstrapTicker() {
    initRows();
    setRefreshStatusState('ok');
    updateRefreshStatus(isPaused ? '自动刷新已暂停（切回页面继续）' : '自动刷新中');
    await refreshTokens();
    if (!isPaused) {
      startTicker();
    }
  }

  function tryResumeAfterError() {
    if (!isAutoRefreshDisabled) {
      return;
    }
    setManualLoading(true);
    refreshTokens()
      .finally(() => {
        setManualLoading(false);
        if (!document.hidden && !isPaused) {
          startTicker();
        }
      });
  }

  refreshStatusEl?.addEventListener('click', () => {
    if (refreshStatusEl?.dataset?.state === 'error') {
      tryResumeAfterError();
    }
  });
  refreshStatusEl?.addEventListener('keydown', (event) => {
    if (refreshStatusEl?.dataset?.state !== 'error') {
      return;
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      tryResumeAfterError();
    }
  });

  tbody.addEventListener('click', (event) => {
    const badge = event.target.closest('.code-badge');
    if (badge && badge.dataset.code) {
      const row = badge.closest('tr');
      const btn = row ? row.querySelector('.copy-btn') : null;
      if (btn && btn.dataset.code) {
        btn.click();
      }
      return;
    }
    const btn = event.target.closest('.copy-btn');
    if (!btn || !btn.dataset.code) {
      return;
    }
    if (window.appCopyWithFeedback) {
      window.appCopyWithFeedback(btn, btn.dataset.code, {
        successHtml: '已复制',
        failureHtml: '复制失败',
        successAnnounce: '验证码已复制',
        failureAnnounce: '复制失败',
        restoreMs: 1200,
        successClass: 'btn-success',
        failureClass: 'btn-danger',
        clearClasses: ['btn-outline-secondary'],
        toastFailure: '复制失败，请检查浏览器权限或手动复制。',
      }).catch((err) => console.error('Copy failed:', err));
      return;
    }
    const original = btn.dataset.labelDefault || btn.innerHTML;
    (window.appCopyToClipboard ? window.appCopyToClipboard(btn.dataset.code) : Promise.reject(new Error('copy_not_supported')))
      .then(() => {
        btn.classList.remove('btn-outline-secondary');
        btn.classList.add('btn-success');
        btn.innerHTML = '已复制';
        if (window.appAnnounce) {
          window.appAnnounce('验证码已复制');
        }
        setTimeout(() => {
          btn.classList.remove('btn-success');
          btn.classList.add('btn-outline-secondary');
          btn.innerHTML = original;
        }, 1200);
      })
      .catch((err) => {
        console.error('Copy failed:', err);
        btn.classList.remove('btn-outline-secondary');
        btn.classList.add('btn-danger');
        btn.innerHTML = '复制失败';
        if (window.appToast) {
          window.appToast('danger', '复制失败，请检查浏览器权限或手动复制。');
        }
        if (window.appAnnounce) {
          window.appAnnounce('复制失败');
        }
        setTimeout(() => {
          btn.classList.remove('btn-danger');
          btn.classList.add('btn-outline-secondary');
          btn.innerHTML = original;
        }, 1400);
      });
  });

  tbody.addEventListener('keydown', (event) => {
    const badge = event.target && event.target.closest ? event.target.closest('.code-badge') : null;
    if (!badge || !badge.dataset.code) {
      return;
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      const row = badge.closest('tr');
      const btn = row ? row.querySelector('.copy-btn') : null;
      if (btn && btn.dataset.code) {
        btn.click();
      }
    }
  });

  tbody.addEventListener('click', (event) => {
    const trigger = event.target.closest('.rename-btn');
    if (!trigger || !renameModalEl) {
      return;
    }
    event.preventDefault();
    const tr = trigger.closest('tr[data-rename-url]');
    if (!tr) {
      return;
    }
    const url = tr.dataset.renameUrl || '';
    if (!url) {
      return;
    }
    renameTargetRow = tr;
    renameSubmitUrl = url;
    if (renameEntryIdInput) {
      renameEntryIdInput.value = tr.dataset.id || '';
    }
    const currentName = trigger.dataset.entryName
      || tr.querySelector('.entry-name')?.textContent?.trim()
      || '';
    if (renameNameInput) {
      renameNameInput.value = currentName;
    }
    inlineAlert(renameAlert, 'danger', '');
    setRenameLoading(false);
    renameModalInstance =
      window.bootstrap && typeof window.bootstrap.Modal === 'function'
        ? window.bootstrap.Modal.getOrCreateInstance(renameModalEl)
        : null;
    if (renameModalInstance) {
      renameModalInstance.show();
    }
  });

  manualRefreshBtn?.addEventListener('click', () => {
    if (pendingRequest) {
      return;
    }
    setManualLoading(true);
    refreshTokens()
      .catch((err) => {
        console.error('Manual refresh failed:', err);
        if (window.appToast) {
          window.appToast('danger', '刷新失败，请稍后再试。');
        }
      })
      .finally(() => {
        setManualLoading(false);
        if (!isPaused) {
          startTicker();
        }
      });
  });

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      pauseAutoRefresh();
    } else {
      resumeAutoRefresh();
    }
  });

  bootstrapTicker();

  renameForm?.addEventListener('submit', (event) => {
    event.preventDefault();
    renameSubmitBtn?.click();
  });

  renameNameInput?.addEventListener('input', () => {
    inlineAlert(renameAlert, 'danger', '');
  });

  renameSubmitBtn?.addEventListener('click', () => {
    if (!renameTargetRow || !renameSubmitUrl || !renameNameInput) {
      return;
    }
    if (renameForm && typeof renameForm.checkValidity === 'function' && !renameForm.checkValidity()) {
      renameForm.classList.add('was-validated');
      if (window.appFocusFirstInvalid) {
        window.appFocusFirstInvalid(renameForm, { toastMessage: '请检查填写内容后再提交。' });
      } else {
        focusElement(renameNameInput);
      }
      if (window.appNotify) {
        window.appNotify({ alertEl: renameAlert, variant: 'warning', message: '请检查填写内容后再提交。' });
      }
      return;
    }
    const value = renameNameInput.value.trim();
    if (!value) {
      showRenameError('名称不能为空');
      focusElement(renameNameInput);
      return;
    }

    inlineAlert(renameAlert, 'danger', '');
    setRenameLoading(true);

    const formData = new FormData();
    formData.append('name', value);

    fetch(renameSubmitUrl, {
      method: 'POST',
      headers: {
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
        'X-Requested-With': 'fetch',
      },
      body: formData,
      credentials: 'same-origin',
    })
      .then(async (resp) => {
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || !data.ok) {
          const message = data.message || '保存失败，请稍后再试';
          throw new Error(message);
        }
        return data;
      })
      .then((data) => {
        const newName = data.name || value;
        const nameEl = renameTargetRow?.querySelector('.entry-name');
        if (nameEl) {
          nameEl.textContent = newName;
          nameEl.title = newName;
        }
        const renameBtn = renameTargetRow?.querySelector('.rename-btn');
        if (renameBtn) {
          renameBtn.dataset.entryName = newName;
          renameBtn.setAttribute('aria-label', `重命名 ${newName}`);
        }
        const shareBtn = renameTargetRow?.querySelector('.share-link-btn');
        if (shareBtn) {
          shareBtn.dataset.entryName = newName;
        }
        if (renameModalInstance) {
          renameModalInstance.hide();
        } else {
          resetRenameModal();
        }
      })
      .catch((err) => {
        showRenameError(err.message || '保存失败，请稍后再试');
        focusElement(renameNameInput, { select: true });
      })
      .finally(() => {
        setRenameLoading(false);
      });
  });

  renameModalEl?.addEventListener('shown.bs.modal', () => {
    focusElement(renameNameInput, { select: true });
  });

  renameModalEl?.addEventListener('hidden.bs.modal', () => {
    resetRenameModal();
  });

  TotpImportModal?.init({
    modalId: 'importModal',
    previewUrl: importPreviewUrl,
    applyUrl: importApplyUrl,
    defaultSpace: config.defaultSpace || 'personal',
  });

  tbody.addEventListener('change', (event) => {
    const select = event.target.closest('.group-select');
    if (!select) {
      return;
    }
    const tr = select.closest('tr[data-update-url]');
    if (!tr) {
      return;
    }
    const url = tr.dataset.updateUrl;
    const previous = select.dataset.current ?? '';
    const value = select.value;
    select.disabled = true;
    select.classList.remove('is-valid', 'is-invalid');
    const formData = new FormData();
    formData.append('group_id', value);
    fetch(url, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'fetch',
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
      },
      body: formData,
    })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.json();
      })
      .then(() => {
        select.dataset.current = value;
        select.classList.add('is-valid');
        setTimeout(() => select.classList.remove('is-valid'), 1200);
      })
      .catch((err) => {
        console.error('Update group failed:', err);
        if (window.appToast) {
          window.appToast('danger', '更新分组失败，请稍后再试。');
        }
        select.value = previous;
        select.classList.add('is-invalid');
        setTimeout(() => select.classList.remove('is-invalid'), 1500);
      })
      .finally(() => {
        select.disabled = false;
      });
  });

  tbody.addEventListener('change', (event) => {
    const select = event.target.closest('.asset-select');
    if (!select) {
      return;
    }
    const tr = select.closest('tr[data-update-asset-url]');
    if (!tr) {
      return;
    }
    const url = tr.dataset.updateAssetUrl;
    const previous = select.dataset.current ?? '';
    const value = select.value;
    select.disabled = true;
    select.classList.remove('is-valid', 'is-invalid');
    const formData = new FormData();
    formData.append('asset_id', value);
    fetch(url, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'fetch',
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
      },
      body: formData,
    })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.json();
      })
      .then(() => {
        select.dataset.current = value;
        select.classList.add('is-valid');
        setTimeout(() => select.classList.remove('is-valid'), 1200);
      })
      .catch((err) => {
        console.error('Update asset failed:', err);
        if (window.appToast) {
          window.appToast('danger', '更新资产归属失败，请稍后再试。');
        }
        select.value = previous;
        select.classList.add('is-invalid');
        setTimeout(() => select.classList.remove('is-invalid'), 1500);
      })
      .finally(() => {
        select.disabled = false;
      });
  });

  function updateClearButton() {
    const hasValue = (qInput && qInput.value.trim()) || (groupSelect && groupSelect.value) || (assetSelect && assetSelect.value);
    if (clearBtn) {
      clearBtn.classList.toggle('d-none', !hasValue);
    }
  }

  updateClearButton();

  if (qInput) {
    qInput.addEventListener('input', updateClearButton);
  }
  if (groupSelect) {
    groupSelect.addEventListener('change', updateClearButton);
  }
  if (assetSelect) {
    assetSelect.addEventListener('change', updateClearButton);
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (qInput) {
        qInput.value = '';
      }
      if (groupSelect) {
        groupSelect.value = '';
      }
      if (assetSelect) {
        assetSelect.value = '';
      }
      updateClearButton();
      if (form) {
        form.submit();
      }
    });
  }

  if (form) {
    form.addEventListener('submit', () => {
      if (qInput) {
        qInput.value = qInput.value.trim();
      }
      if (searchBtn) {
        searchBtn.disabled = true;
      }
      if (spinner) {
        spinner.classList.remove('d-none');
      }
    });
  }

  document.addEventListener('keydown', (event) => {
    const key = event.key;
    const target = event.target;
    const isTypingTarget = target instanceof HTMLElement
      && (target.isContentEditable
        || target.tagName === 'INPUT'
        || target.tagName === 'TEXTAREA'
        || target.tagName === 'SELECT');
    if (key === '/' && !isTypingTarget) {
      if (qInput) {
        event.preventDefault();
        focusElement(qInput, { select: true });
      }
      return;
    }
    if (key === 'Escape' && qInput && document.activeElement === qInput && qInput.value) {
      qInput.value = '';
      updateClearButton();
    }
  });

  const addGroupModalEl = document.getElementById('addGroupModal');
  const groupManageList = document.getElementById('groupManageList');
  const groupManageAlert = document.getElementById('groupManageAlert');
  const groupManageEmpty = document.getElementById('groupManageEmpty');

  function clearGroupManageAlert() {
    inlineAlert(groupManageAlert, 'danger', '');
  }

  function showGroupManageAlert(kind, message) {
    const variant = kind === 'success' ? 'success' : kind === 'warning' ? 'warning' : 'danger';
    notify(groupManageAlert, variant, message);
  }

  function refreshGroupManageEmptyState() {
    if (!groupManageList || !groupManageEmpty) {
      return;
    }
    const hasItems = Boolean(groupManageList.querySelector('[data-group-id]'));
    groupManageEmpty.classList.toggle('d-none', hasItems);
  }

  function setGroupRowPending(row, pending, activeBtn, label) {
    const input = row.querySelector('.group-name-input');
    if (input) {
      input.disabled = pending;
    }
    row.querySelectorAll('button').forEach((btn) => {
      if (pending) {
        if (btn === activeBtn && window.appSetButtonLoading) {
          window.appSetButtonLoading(btn, true, { label: label || '' });
        } else {
          btn.disabled = true;
        }
      } else {
        if (window.appSetButtonLoading) {
          window.appSetButtonLoading(btn, false);
        } else {
          btn.disabled = false;
          if (btn.dataset.originalLabel) {
            btn.innerHTML = btn.dataset.originalLabel;
            delete btn.dataset.originalLabel;
          }
        }
      }
    });
  }

  function updateGroupOptions(groupId, label) {
    if (!groupId) {
      return;
    }
    const value = String(groupId);
    const filterSelect = document.getElementById('group');
    const filterOption = filterSelect ? filterSelect.querySelector(`option[value="${value}"]`) : null;
    if (filterOption) {
      filterOption.textContent = label;
    }
    document.querySelectorAll('select.group-select').forEach((select) => {
      const option = select.querySelector(`option[value="${value}"]`);
      if (option) {
        option.textContent = label;
      }
    });
  }

  function removeGroupOptions(groupId) {
    if (!groupId) {
      return;
    }
    const value = String(groupId);
    const filterSelect = document.getElementById('group');
    const filterOption = filterSelect ? filterSelect.querySelector(`option[value="${value}"]`) : null;
    filterOption?.remove();
    document.querySelectorAll('select.group-select').forEach((select) => {
      const option = select.querySelector(`option[value="${value}"]`);
      if (option) {
        if (select.value === value) {
          select.value = '';
          select.dataset.current = '';
        }
        option.remove();
      }
    });
  }

  function handleGroupRename(row, trigger) {
    const input = row.querySelector('.group-name-input');
    const url = row.dataset.renameUrl;
    if (!input || !url) {
      return;
    }
    const newName = (input.value || '').trim();
    if (!newName) {
      showGroupManageAlert('error', '分组名称不能为空');
      input.focus();
      return;
    }
    clearGroupManageAlert();
    setGroupRowPending(row, true, trigger, '保存中...');
    const payload = new URLSearchParams();
    payload.append('name', newName);
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
        'X-Requested-With': 'fetch',
      },
      body: payload,
      credentials: 'same-origin',
    })
      .then(async (resp) => {
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || !data.ok) {
          const message = data.message || '保存失败，请稍后再试';
          throw new Error(message);
        }
        return data;
      })
      .then((data) => {
        input.value = data.name;
        updateGroupOptions(row.dataset.groupId, data.name);
        showGroupManageAlert('success', '分组名称已更新');
      })
      .catch((err) => {
        showGroupManageAlert('error', err.message || '保存失败，请稍后再试');
      })
      .finally(() => {
        setGroupRowPending(row, false, trigger);
      });
  }

  async function handleGroupDelete(row, trigger) {
    const url = row.dataset.deleteUrl;
    const groupId = row.dataset.groupId;
    if (!url || !groupId) {
      return;
    }
    const count = Number(row.dataset.entryCount || '0');
    const message =
      count > 0
        ? `该分组下还有 ${count} 条密钥，删除后将移动到“未分组”。是否继续？`
        : '确定删除该分组？';
    const confirmed = window.appConfirm
      ? await window.appConfirm({
          title: '删除分组',
          message,
          confirmText: '删除',
          confirmVariant: 'danger',
        })
      : window.confirm(message);
    if (!confirmed) {
      return;
    }
    clearGroupManageAlert();
    setGroupRowPending(row, true, trigger, '删除中...');
    fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
        'X-Requested-With': 'fetch',
      },
      credentials: 'same-origin',
    })
      .then(async (resp) => {
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || !data.ok) {
          const message = data.message || '删除失败，请稍后再试';
          throw new Error(message);
        }
        return data;
      })
      .then((data) => {
        removeGroupOptions(groupId);
        row.remove();
        refreshGroupManageEmptyState();
        const released = Number.isFinite(Number(data.released_entries)) ? Number(data.released_entries) : 0;
        showGroupManageAlert(
          'success',
          released > 0
            ? `已删除分组，${released} 条密钥已移动到“未分组”`
            : '已删除分组'
        );
      })
      .catch((err) => {
        showGroupManageAlert('error', err.message || '删除失败，请稍后再试');
      })
      .finally(() => {
        setGroupRowPending(row, false, trigger);
      });
  }

  groupManageList?.addEventListener('click', (event) => {
    const row = event.target.closest('[data-group-id]');
    if (!row) {
      return;
    }
    if (event.target.closest('.group-save-btn')) {
      handleGroupRename(row, event.target.closest('button'));
    } else if (event.target.closest('.group-delete-btn')) {
      handleGroupDelete(row, event.target.closest('button'));
    }
  });

  groupManageList?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') {
      return;
    }
    const input = event.target.closest('.group-name-input');
    if (!input) {
      return;
    }
    event.preventDefault();
    const row = input.closest('[data-group-id]');
    if (row) {
      handleGroupRename(row, row.querySelector('.group-save-btn'));
    }
  });

  addGroupModalEl?.addEventListener('hidden.bs.modal', () => {
    clearGroupManageAlert();
  });

  refreshGroupManageEmptyState();

  const shareModalEl = document.getElementById('shareLinkModal');
  const shareLinkEntryLabel = document.getElementById('shareLinkEntryLabel');
  const shareLinkForm = document.getElementById('shareLinkForm');
  const shareLinkEntryId = document.getElementById('shareLinkEntryId');
  const shareLinkDuration = document.getElementById('shareLinkDuration');
  const shareLinkMaxViews = document.getElementById('shareLinkMaxViews');
  const shareLinkNote = document.getElementById('shareLinkNote');
  const shareLinkResult = document.getElementById('shareLinkResult');
  const shareLinkAlert = document.getElementById('shareLinkAlert');
  const shareLinkUrl = document.getElementById('shareLinkUrl');
  const shareLinkCopyBtn = document.getElementById('shareLinkCopyBtn');
  const shareLinkSubmitBtn = document.getElementById('shareLinkSubmitBtn');
  const shareLinkSpinner = document.getElementById('shareLinkSpinner');
  const shareLinkSummary = document.getElementById('shareLinkSummary');
  const shareLinkInvalidateBtn = document.getElementById('shareLinkInvalidateBtn');
  const paginationEl = document.getElementById('entryListPagination');
  let shareModalInstance = null;

  function clearShareLinkAlert() {
    inlineAlert(shareLinkAlert, 'danger', '');
  }

  function showShareLinkAlert(kind, message) {
    const variant = kind === 'success' ? 'success' : kind === 'warning' ? 'warning' : 'danger';
    notify(shareLinkAlert, variant, message);
  }

  function resetShareModal() {
    clearShareLinkAlert();
    shareLinkResult?.classList.add('d-none');
    if (shareLinkUrl) {
      shareLinkUrl.value = '';
    }
    shareLinkSummary?.replaceChildren();
    if (shareLinkInvalidateBtn) {
      shareLinkInvalidateBtn.classList.add('d-none');
      shareLinkInvalidateBtn.dataset.linkId = '';
      shareLinkInvalidateBtn.disabled = false;
    }
    if (shareLinkDuration) {
      shareLinkDuration.value = '10';
    }
    if (shareLinkMaxViews) {
      shareLinkMaxViews.value = '3';
    }
    if (shareLinkNote) {
      shareLinkNote.value = '';
    }
    if (shareLinkSpinner) {
      shareLinkSpinner.classList.add('d-none');
    }
    if (shareLinkSubmitBtn) {
      shareLinkSubmitBtn.disabled = false;
    }
    shareLinkForm?.classList.remove('was-validated');
  }

  function refreshEntryListFragment() {
    const url = window.location.href.split('#')[0];
    return fetch(url, { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.text();
      })
      .then((html) => {
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const nextTbody = doc.getElementById('tbody');
        if (nextTbody) {
          tbody.innerHTML = nextTbody.innerHTML;
        }
        const nextPagination = doc.getElementById('entryListPagination');
        if (paginationEl) {
          paginationEl.innerHTML = nextPagination ? nextPagination.innerHTML : '';
          paginationEl.classList.toggle('d-none', !nextPagination);
        }
        initRows();
      });
  }

  function setShareSubmitting(flag) {
    if (!shareLinkSubmitBtn) {
      return;
    }
    if (window.appSetButtonLoading) {
      window.appSetButtonLoading(shareLinkSubmitBtn, flag, { label: '生成中' });
      return;
    }
    shareLinkSubmitBtn.disabled = flag;
    if (shareLinkSpinner) {
      shareLinkSpinner.classList.toggle('d-none', !flag);
    }
  }

  function resolveShareLinkUrl(payload) {
    const rawValue = payload?.path || payload?.url || '';
    if (!rawValue) {
      return '';
    }
    try {
      const absoluteUrl = new URL(rawValue, window.location.href);
      return `${window.location.origin}${absoluteUrl.pathname}${absoluteUrl.search}${absoluteUrl.hash}`;
    } catch (error) {
      console.error('Resolve share link url failed:', error);
      return rawValue;
    }
  }

  function handleShareLinkCreateSuccess(data) {
    const shareUrl = resolveShareLinkUrl(data);
    if (shareLinkUrl) {
      shareLinkUrl.value = shareUrl;
    }
    if (shareLinkResult) {
      shareLinkResult.classList.remove('d-none');
    }
    renderShareSummary(data);
    if (shareLinkInvalidateBtn) {
      shareLinkInvalidateBtn.classList.remove('d-none');
      shareLinkInvalidateBtn.dataset.linkId = String(data.id || '');
    }
    showShareLinkAlert('success', '分享链接已生成，可直接复制并发送。');

    if (shareUrl && window.appCopyToClipboard) {
      window.appCopyToClipboard(shareUrl)
        .then(() => {
          if (window.appToast) {
            window.appToast('success', '分享链接已生成并复制。');
          }
        })
        .catch(() => {
          if (window.appToast) {
            window.appToast('info', '分享链接已生成，请手动复制。');
          }
        });
    }

    refreshEntryListFragment().catch((err) => {
      console.error('Refresh entries after link creation failed:', err);
    });
  }

  function renderShareSummary(payload) {
    if (!shareLinkSummary) {
      return;
    }
    shareLinkSummary.replaceChildren();
    if (!payload) {
      return;
    }
    if (payload.created_at) {
      const created = new Date(payload.created_at);
      const li = document.createElement('li');
      li.textContent = `创建时间：${created.toLocaleString()}`;
      shareLinkSummary.appendChild(li);
    }
    if (payload.expires_at) {
      const expires = new Date(payload.expires_at);
      const li = document.createElement('li');
      li.textContent = `有效期至：${expires.toLocaleString()}`;
      shareLinkSummary.appendChild(li);
    }
    if (payload.duration_minutes) {
      const li = document.createElement('li');
      li.textContent = `有效期：${payload.duration_minutes} 分钟`;
      shareLinkSummary.appendChild(li);
    }
    if (typeof payload.max_views !== 'undefined') {
      const remaining = payload.remaining_views ?? Math.max(0, payload.max_views - 1);
      const li = document.createElement('li');
      li.textContent = `最多查看 ${payload.max_views} 次，目前还可查看 ${remaining} 次。`;
      shareLinkSummary.appendChild(li);
    }
    if (payload.note) {
      const li = document.createElement('li');
      li.textContent = `备注：${payload.note}`;
      shareLinkSummary.appendChild(li);
    }
  }

  tbody.addEventListener('click', (event) => {
    const trigger = event.target.closest('.share-link-btn');
    if (!trigger || !shareModalEl || !shareLinkEntryId || !shareLinkEntryLabel) {
      return;
    }
    const entryId = trigger.dataset.entryId;
    const entryName = trigger.dataset.entryName || `#${entryId}`;
    shareLinkEntryId.value = entryId;
    shareLinkEntryLabel.textContent = entryName;
    resetShareModal();
    if (window.bootstrap && typeof window.bootstrap.Modal === 'function') {
      shareModalInstance = window.bootstrap.Modal.getOrCreateInstance(shareModalEl);
      shareModalInstance.show();
    }
  });

  shareModalEl?.addEventListener('hidden.bs.modal', () => {
    if (shareLinkEntryId) {
      shareLinkEntryId.value = '';
    }
    resetShareModal();
  });

  shareLinkSubmitBtn?.addEventListener('click', () => {
    if (!shareLinkEntryId?.value) {
      return;
    }
    clearShareLinkAlert();
    setShareSubmitting(true);
    const formData = new FormData();
    formData.append('duration', shareLinkDuration?.value || '10');
    formData.append('max_views', shareLinkMaxViews?.value || '3');
    formData.append('note', (shareLinkNote?.value || '').trim());

    const createUrl = (config.oneTimeCreateUrlTemplate || '').replace('/0/', `/${shareLinkEntryId.value}/`);
    fetch(createUrl, {
      method: 'POST',
      headers: {
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
        'X-Requested-With': 'fetch',
      },
      body: formData,
    })
      .then(async (resp) => {
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || !data.ok) {
          const message = data.message || '生成链接失败，请稍后重试。';
          throw new Error(message);
        }
        handleShareLinkCreateSuccess(data);
      })
      .catch((err) => {
        showShareLinkAlert('danger', err.message || '生成链接失败，请稍后重试。');
      })
      .finally(() => setShareSubmitting(false));
  });

  shareLinkCopyBtn?.addEventListener('click', () => {
    if (!shareLinkUrl?.value) {
      return;
    }
    (window.appCopyToClipboard ? window.appCopyToClipboard(shareLinkUrl.value) : Promise.reject(new Error('copy_not_supported')))
      .then(() => {
        shareLinkCopyBtn.classList.remove('btn-outline-success');
        shareLinkCopyBtn.classList.add('btn-success');
        shareLinkCopyBtn.textContent = '已复制';
        setTimeout(() => {
          shareLinkCopyBtn.classList.remove('btn-success');
          shareLinkCopyBtn.classList.add('btn-outline-success');
          shareLinkCopyBtn.textContent = '复制';
        }, 1600);
      })
      .catch(() => {
        showShareLinkAlert('danger', '复制失败，请手动复制链接。');
      });
  });

  shareLinkInvalidateBtn?.addEventListener('click', () => {
    const linkId = shareLinkInvalidateBtn.dataset.linkId;
    if (!linkId) {
      return;
    }
    const invalidateUrl = (config.oneTimeInvalidateUrlTemplate || '').replace('/0/', `/${linkId}/`);
    shareLinkInvalidateBtn.disabled = true;
    fetch(invalidateUrl, {
      method: 'POST',
      headers: {
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
        'X-Requested-With': 'fetch',
      },
    })
      .then(async (resp) => {
        const data = await resp.json().catch(() => ({}));
        if (data?.error === 'reauth_required' && data?.redirect) {
          window.location.href = data.redirect;
          return;
        }
        if (!resp.ok || !data.ok) {
          throw new Error(data.message || '未能立即失效，请稍后再试。');
        }
        showShareLinkAlert('success', '链接已失效。');
        shareLinkInvalidateBtn.classList.add('d-none');
        shareLinkInvalidateBtn.dataset.linkId = '';
      })
      .catch((err) => {
        showShareLinkAlert('danger', err.message || '未能立即失效，请稍后再试。');
      })
      .finally(() => {
        shareLinkInvalidateBtn.disabled = false;
      });
  });

  const params = new URLSearchParams(window.location.search);
  const modal = params.get('modal');
  if (modal === 'add' || modal === 'import' || modal === 'export_encrypted') {
    const id = modal === 'add' ? 'addModal' : (modal === 'import' ? 'importModal' : 'exportEncryptedModal');
    const element = document.getElementById(id);
    if (element && window.bootstrap && typeof window.bootstrap.Modal === 'function') {
      new window.bootstrap.Modal(element).show();
    }
  }
})();
