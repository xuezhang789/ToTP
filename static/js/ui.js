(() => {
  function ensureBootstrap() {
    return window.bootstrap || null;
  }

  function setText(el, value) {
    if (!el) return;
    el.textContent = value == null ? '' : String(value);
  }

  function appToast(type, message, { delay = 2500 } = {}) {
    const bootstrap = ensureBootstrap();
    const container = document.getElementById('appToastContainer');
    if (!bootstrap || !container) {
      return;
    }
    const variant = type === 'success' || type === 'danger' || type === 'warning' || type === 'info'
      ? type
      : 'info';
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${variant} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML = `
      <div class="d-flex">
        <div class="toast-body"></div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="关闭"></button>
      </div>
    `;
    const body = toastEl.querySelector('.toast-body');
    setText(body, message);
    container.appendChild(toastEl);
    const instance = new bootstrap.Toast(toastEl, { delay });
    toastEl.addEventListener('hidden.bs.toast', () => {
      toastEl.remove();
    });
    instance.show();
  }

  function appInlineAlert(alertEl, variant, message) {
    if (!alertEl) {
      return false;
    }
    const text = message == null ? '' : String(message);
    const level = variant === 'success' || variant === 'warning' || variant === 'info' ? variant : 'danger';
    alertEl.classList.remove('alert-success', 'alert-warning', 'alert-info', 'alert-danger');
    alertEl.classList.add(`alert-${level}`);
    alertEl.textContent = text;
    alertEl.classList.toggle('d-none', !text);
    return Boolean(text);
  }

  function appNotify({ alertEl = null, variant = 'danger', message = '', toastVariant = null } = {}) {
    const shown = appInlineAlert(alertEl, variant, message);
    if (shown) {
      return;
    }
    if (typeof appToast === 'function') {
      appToast(toastVariant || variant, message);
    }
  }

  function getConfirmElements() {
    return {
      modalEl: document.getElementById('appConfirmModal'),
      titleEl: document.getElementById('appConfirmTitle'),
      messageEl: document.getElementById('appConfirmMessage'),
      hintEl: document.getElementById('appConfirmHint'),
      okBtn: document.getElementById('appConfirmOkBtn'),
      cancelBtn: document.getElementById('appConfirmCancelBtn'),
    };
  }

  function appConfirm({
    title = '请确认操作',
    message = '',
    confirmText = '确认',
    confirmVariant = 'danger',
    hint = '',
  } = {}) {
    const bootstrap = ensureBootstrap();
    const { modalEl, titleEl, messageEl, hintEl, okBtn, cancelBtn } = getConfirmElements();
    if (!bootstrap || !modalEl || !okBtn || !cancelBtn) {
      return Promise.resolve(window.confirm(message || title));
    }

    setText(titleEl, title);
    setText(messageEl, message);
    okBtn.textContent = confirmText;
    okBtn.classList.remove('btn-primary', 'btn-danger', 'btn-warning', 'btn-success', 'btn-outline-primary');
    okBtn.classList.add(confirmVariant === 'primary' ? 'btn-primary' : (confirmVariant === 'warning' ? 'btn-warning' : 'btn-danger'));

    if (hint) {
      setText(hintEl, hint);
      hintEl.classList.remove('d-none');
    } else if (hintEl) {
      hintEl.textContent = '';
      hintEl.classList.add('d-none');
    }

    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    return new Promise((resolve) => {
      let settled = false;
      function cleanup() {
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
        modalEl.removeEventListener('hidden.bs.modal', onHidden);
      }
      function settle(value) {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      }
      function onOk() {
        modal.hide();
        settle(true);
      }
      function onCancel() {
        settle(false);
      }
      function onHidden() {
        settle(false);
      }
      okBtn.addEventListener('click', onOk, { once: true });
      cancelBtn.addEventListener('click', onCancel, { once: true });
      modalEl.addEventListener('hidden.bs.modal', onHidden, { once: true });
      modal.show();
    });
  }

  function isFormSubmitElement(el) {
    if (!el) return false;
    if (el.tagName === 'BUTTON' && (el.type === '' || el.type === 'submit')) return true;
    if (el.tagName === 'INPUT' && el.type === 'submit') return true;
    return false;
  }

  function submitFormSafely(form, submitter) {
    if (!form) return;
    if (form.dataset.confirmBypassed === '1') {
      form.dataset.confirmBypassed = '';
      form.submit();
      return;
    }
    form.dataset.confirmBypassed = '1';
    if (form.requestSubmit) {
      form.requestSubmit(submitter instanceof HTMLElement ? submitter : undefined);
      return;
    }
    if (submitter && submitter.getAttribute) {
      const name = submitter.getAttribute('name');
      const value = submitter.getAttribute('value');
      if (name) {
        const hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = name;
        hidden.value = value || '';
        form.appendChild(hidden);
      }
    }
    form.submit();
  }

  function getConfirmPayload(el) {
    const message = el.getAttribute('data-confirm') || '';
    const title = el.getAttribute('data-confirm-title') || '请确认操作';
    const confirmText = el.getAttribute('data-confirm-ok') || '确认';
    const variant = el.getAttribute('data-confirm-variant') || 'danger';
    const hint = el.getAttribute('data-confirm-hint') || '';
    return { title, message, confirmText, confirmVariant: variant, hint };
  }

  document.addEventListener('click', async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const el = target.closest('[data-confirm]');
    if (!el) return;

    const isLink = el.tagName === 'A' && el.getAttribute('href');
    const isSubmit = isFormSubmitElement(el);
    const form = isSubmit ? el.form || el.closest('form') : el.closest('form');
    if (!isLink && !form) {
      return;
    }

    event.preventDefault();
    const ok = await appConfirm(getConfirmPayload(el));
    if (!ok) {
      return;
    }
    if (isLink) {
      window.location.href = el.getAttribute('href');
      return;
    }
    submitFormSafely(form, isSubmit ? el : null);
  });

  window.appToast = appToast;
  window.appInlineAlert = appInlineAlert;
  window.appNotify = appNotify;
  window.appConfirm = appConfirm;
})();
