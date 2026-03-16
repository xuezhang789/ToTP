(() => {
  const batchBtn = document.getElementById('batchInvalidateBtn');
  const remindBtn = document.getElementById('batchRemindBtn');
  const master = document.getElementById('selectAllLinks');
  const selectedCountEl = document.getElementById('selectedCount');
  const checkboxes = Array.from(document.querySelectorAll('[data-link-select]'));
  if (!checkboxes.length) {
    return;
  }

  function getSelectedIds() {
    return checkboxes
      .filter((cb) => cb.checked)
      .map((cb) => Number(cb.value))
      .filter((value) => Number.isFinite(value) && value > 0);
  }

  function updateUI() {
    const selected = getSelectedIds();
    if (selectedCountEl) {
      selectedCountEl.textContent = String(selected.length);
    }
    if (batchBtn) {
      batchBtn.disabled = selected.length === 0;
    }
    if (remindBtn) {
      remindBtn.disabled = selected.length === 0;
    }
    if (master) {
      const checkedCount = selected.length;
      master.checked = checkedCount > 0 && checkedCount === checkboxes.length;
      master.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
    }
  }

  master?.addEventListener('change', () => {
    const checked = Boolean(master.checked);
    checkboxes.forEach((cb) => {
      cb.checked = checked;
    });
    updateUI();
  });

  checkboxes.forEach((cb) => cb.addEventListener('change', updateUI));
  updateUI();

  async function runBatchAction(btn, { title, message, confirmText, confirmVariant, hint }) {
    const ids = getSelectedIds();
    if (!ids.length) {
      return;
    }
    const ok = window.appConfirm
      ? await window.appConfirm({
        title,
        message: message(ids.length),
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
      body: JSON.stringify({ ids }),
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
    const ids = getSelectedIds();
    if (!ids.length) {
      return;
    }
    runBatchAction(batchBtn, {
      title: '批量失效链接',
      message: (count) => `确定要失效选中的 ${count} 条链接吗？`,
      confirmText: '失效',
      confirmVariant: 'danger',
      hint: '失效后接收者将无法再访问该链接。',
    });
  });

  remindBtn?.addEventListener('click', async () => {
    runBatchAction(remindBtn, {
      title: '批量提醒成员失效',
      message: (count) => `确定要提醒相关成员尽快失效选中的 ${count} 条链接吗？`,
      confirmText: '提醒',
      confirmVariant: 'primary',
      hint: '系统将通过邮件提醒链接创建人处理。',
    });
  });
})();
