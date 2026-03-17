(() => {
  const batchBtn = document.getElementById('batchInvalidateBtn');
  const remindBtn = document.getElementById('batchRemindBtn');
  const master = document.getElementById('selectAllLinks');
  const masterMobile = document.getElementById('selectAllLinksMobile');
  const selectedCountEl = document.getElementById('selectedCount');
  const selectedActiveCountEl = document.getElementById('selectedActiveCount');
  const checkboxes = Array.from(document.querySelectorAll('[data-link-select]'));
  if (!checkboxes.length) {
    return;
  }

  function getVisibleCheckboxes() {
    return checkboxes.filter((cb) => cb.offsetParent !== null);
  }

  function getSelectedIds() {
    const visible = getVisibleCheckboxes();
    return visible
      .filter((cb) => cb.checked)
      .map((cb) => Number(cb.value))
      .filter((value) => Number.isFinite(value) && value > 0);
  }

  function getSelectedActiveCount() {
    const visible = getVisibleCheckboxes();
    return visible.filter((cb) => cb.checked && cb.dataset.statusKey === 'active').length;
  }

  function updateUI() {
    const selected = getSelectedIds();
    const visible = getVisibleCheckboxes();
    if (selectedCountEl) {
      selectedCountEl.textContent = String(selected.length);
    }
    if (selectedActiveCountEl) {
      selectedActiveCountEl.textContent = String(getSelectedActiveCount());
    }
    if (batchBtn) {
      batchBtn.disabled = selected.length === 0;
    }
    if (remindBtn) {
      remindBtn.disabled = selected.length === 0;
    }
    if (master) {
      const checkedCount = selected.length;
      master.checked = checkedCount > 0 && checkedCount === visible.length;
      master.indeterminate = checkedCount > 0 && checkedCount < visible.length;
    }
    if (masterMobile) {
      const checkedCount = selected.length;
      masterMobile.checked = checkedCount > 0 && checkedCount === visible.length;
      masterMobile.indeterminate = checkedCount > 0 && checkedCount < visible.length;
    }
  }

  master?.addEventListener('change', () => {
    const checked = Boolean(master.checked);
    getVisibleCheckboxes().forEach((cb) => {
      cb.checked = checked;
    });
    updateUI();
  });

  masterMobile?.addEventListener('change', () => {
    const checked = Boolean(masterMobile.checked);
    getVisibleCheckboxes().forEach((cb) => {
      cb.checked = checked;
    });
    updateUI();
  });

  checkboxes.forEach((cb) => cb.addEventListener('change', updateUI));
  updateUI();

  async function runBatchAction(btn, { title, message, confirmText, confirmVariant, hint, onlyActive = false, ids = null }) {
    const selectedIds = ids || getSelectedIds();
    const selectedActive = selectedIds.filter((id) => {
      const cb = checkboxes.find((x) => Number(x.value) === id);
      return cb && cb.dataset.statusKey === 'active';
    });
    const payloadIds = onlyActive ? selectedActive : selectedIds;
    if (!selectedIds.length) {
      return;
    }
    if (onlyActive && selectedActive.length === 0) {
      if (window.appToast) {
        window.appToast('warning', '所选链接均已失效，无需处理。');
      }
      return;
    }
    const ok = window.appConfirm
      ? await window.appConfirm({
        title,
        message: message(payloadIds.length, selectedIds.length),
        confirmText,
        confirmVariant,
        hint,
        triggerEl: btn,
      })
      : window.confirm('确定要执行该操作吗？');
    if (!ok) {
      return;
    }

    const url = btn.dataset.url || '';
    if (!url) {
      return;
    }
    if (window.appSetButtonLoading) {
      window.appSetButtonLoading(btn, true, { label: '处理中' });
    } else {
      btn.disabled = true;
    }

    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': window.appGetCsrfToken ? window.appGetCsrfToken() : '',
        'X-Requested-With': 'fetch',
      },
      body: JSON.stringify({ ids: payloadIds }),
      credentials: 'same-origin',
    })
      .then(async (resp) => {
        const data = await resp.json().catch(() => ({}));
        if (data?.error === 'reauth_required' && data?.redirect) {
          window.location.href = data.redirect;
          return null;
        }
        if (!resp.ok || !data.ok) {
          throw new Error(data.message || '处理失败，请稍后再试。');
        }
        return data;
      })
      .then((data) => {
        if (!data) {
          return;
        }
        if (window.appToast) {
          window.appToast('success', '操作已完成。');
        }
        window.location.reload();
      })
      .catch((err) => {
        if (window.appToast) {
          window.appToast('danger', err.message || '处理失败，请稍后再试。');
        }
      })
      .finally(() => {
        if (window.appSetButtonLoading) {
          window.appSetButtonLoading(btn, false);
        } else {
          btn.disabled = false;
        }
      });
  }

  batchBtn?.addEventListener('click', async () => {
    runBatchAction(batchBtn, {
      title: '批量失效链接',
      message: (count, selectedTotal) =>
        selectedTotal && selectedTotal !== count
          ? `将失效所选 ${selectedTotal} 条中的 ${count} 条仍可用链接，确定继续吗？`
          : `确定要失效选中的 ${count} 条链接吗？`,
      confirmText: '失效',
      confirmVariant: 'danger',
      hint: '失效后接收者将无法再访问该链接。',
      onlyActive: true,
    });
  });

  remindBtn?.addEventListener('click', async () => {
    runBatchAction(remindBtn, {
      title: '批量提醒成员失效',
      message: (count, selectedTotal) =>
        selectedTotal && selectedTotal !== count
          ? `将提醒所选 ${selectedTotal} 条中的 ${count} 条仍可用链接创建人，确定继续吗？`
          : `确定要提醒相关成员尽快失效选中的 ${count} 条链接吗？`,
      confirmText: '提醒',
      confirmVariant: 'primary',
      hint: '系统将通过邮件提醒链接创建人处理。',
      onlyActive: true,
    });
  });

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const copyBtn = target.closest('.copy-link-id-btn');
    if (copyBtn) {
      const text = copyBtn.getAttribute('data-copy-text') || '';
      if (!text) return;
      (window.appCopyToClipboard ? window.appCopyToClipboard(text) : Promise.reject(new Error('copy_not_supported')))
        .then(() => {
          if (window.appToast) {
            window.appToast('success', '已复制');
          }
        })
        .catch(() => {
          if (window.appToast) {
            window.appToast('danger', '复制失败');
          }
        });
      return;
    }

    const revokeBtn = target.closest('.revoke-link-btn');
    if (revokeBtn) {
      const url = revokeBtn.getAttribute('data-url') || '';
      const linkId = Number(revokeBtn.getAttribute('data-link-id') || '0');
      if (!url || !Number.isFinite(linkId) || linkId <= 0) return;
      runBatchAction(revokeBtn, {
        title: '失效链接',
        message: () => '确定要失效该链接吗？',
        confirmText: '失效',
        confirmVariant: 'danger',
        hint: '失效后接收者将无法再访问该链接。',
        onlyActive: true,
        ids: [linkId],
      });
    }
  });

  const spaceSelect = document.getElementById('auditSpace');
  const teamSelect = document.getElementById('auditTeam');
  function syncSpaceTeam() {
    if (!spaceSelect || !teamSelect) {
      return;
    }
    const space = spaceSelect.value || '';
    const isTeam = space === 'team';
    teamSelect.disabled = space === 'personal';
    if (!isTeam) {
      teamSelect.value = '';
    }
  }
  spaceSelect?.addEventListener('change', syncSpaceTeam);
  syncSpaceTeam();
})();
