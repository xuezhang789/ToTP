(() => {
  function ensureBootstrap() {
    return window.bootstrap || null;
  }

  function setText(el, value) {
    if (!el) return;
    el.textContent = value == null ? '' : String(value);
  }

  function appAnnounce(message) {
    const region = document.getElementById('appLiveRegion');
    if (!region) {
      return;
    }
    const text = message == null ? '' : String(message);
    region.textContent = '';
    window.setTimeout(() => {
      region.textContent = text;
    }, 10);
  }

  function appSetButtonLoading(button, loading, { label = '', showSpinner = true } = {}) {
    if (!button) {
      return;
    }
    if (loading) {
      if (!button.dataset.appOriginalDisabled) {
        button.dataset.appOriginalDisabled = button.disabled ? '1' : '0';
      }
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
      if (!button.dataset.appOriginalHtml) {
        button.dataset.appOriginalHtml = button.innerHTML;
      }
      const base = label || button.dataset.appOriginalHtml || '';
      if (showSpinner) {
        button.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>${base}`;
      } else {
        button.innerHTML = base;
      }
      return;
    }
    button.disabled = button.dataset.appOriginalDisabled === '1';
    button.removeAttribute('aria-busy');
    if (button.dataset.appOriginalHtml != null) {
      button.innerHTML = button.dataset.appOriginalHtml;
    }
  }

  function appCopyWithFeedback(
    button,
    text,
    {
      successHtml = '已复制',
      failureHtml = '复制失败',
      restoreMs = 1200,
      successAnnounce = '已复制',
      failureAnnounce = '复制失败',
      successClass = 'btn-success',
      failureClass = 'btn-danger',
      clearClasses = [],
      toastFailure = '',
    } = {}
  ) {
    if (!button) {
      return Promise.reject(new Error('missing_button'));
    }
    if (button.dataset.appOriginalHtml == null) {
      button.dataset.appOriginalHtml = button.innerHTML;
    }
    if (button.dataset.appOriginalClass == null) {
      button.dataset.appOriginalClass = button.className || '';
    }
    const value = text == null ? '' : String(text);
    return appCopyToClipboard(value)
      .then(() => {
        clearClasses.forEach((cls) => button.classList.remove(cls));
        button.classList.remove(failureClass);
        button.classList.add(successClass);
        button.innerHTML = successHtml;
        if (window.appAnnounce) {
          window.appAnnounce(successAnnounce);
        }
        window.setTimeout(() => {
          button.className = button.dataset.appOriginalClass || button.className;
          button.innerHTML = button.dataset.appOriginalHtml || button.innerHTML;
        }, restoreMs);
        return true;
      })
      .catch((err) => {
        clearClasses.forEach((cls) => button.classList.remove(cls));
        button.classList.remove(successClass);
        button.classList.add(failureClass);
        button.innerHTML = failureHtml;
        if (toastFailure && window.appToast) {
          window.appToast('danger', toastFailure);
        }
        if (window.appAnnounce) {
          window.appAnnounce(failureAnnounce);
        }
        window.setTimeout(() => {
          button.className = button.dataset.appOriginalClass || button.className;
          button.innerHTML = button.dataset.appOriginalHtml || button.innerHTML;
        }, Math.max(restoreMs, 1400));
        throw err;
      });
  }

  function appFocusFirstInvalid(form, { toastMessage = '' } = {}) {
    if (!form) {
      return null;
    }
    const invalid = form.querySelector(':invalid');
    if (invalid && invalid.focus) {
      invalid.focus({ preventScroll: true });
    }
    if (toastMessage && window.appToast) {
      window.appToast('warning', toastMessage);
    }
    return invalid || null;
  }

  function appInitModalAutoFocus() {
    document.addEventListener('shown.bs.modal', (event) => {
      const modal = event && event.target instanceof HTMLElement ? event.target : null;
      if (!modal) {
        return;
      }
      const target = modal.querySelector('[data-autofocus]') || modal.querySelector('input, textarea, select, button');
      if (target && target.focus) {
        target.focus({ preventScroll: true });
        if (target.select && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) {
          try {
            target.select();
          } catch (e) {}
        }
      }
    });
  }

  function appAnnounceFirstMessage() {
    const alert = document.querySelector('main.app-main .alert[role="alert"]');
    if (!alert) {
      return;
    }
    const text = (alert.textContent || '').trim();
    if (text) {
      appAnnounce(text);
    }
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
    toastEl.setAttribute('aria-live', variant === 'danger' ? 'assertive' : 'polite');
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

  function appGetCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function appCopyToClipboard(text) {
    const value = text == null ? '' : String(text);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value);
    }
    const temp = document.createElement('textarea');
    temp.value = value;
    temp.style.position = 'fixed';
    temp.style.opacity = '0';
    document.body.appendChild(temp);
    temp.focus({ preventScroll: true });
    temp.select();
    try {
      const copied = document.execCommand('copy');
      if (!copied) {
        throw new Error('copy_command_failed');
      }
    } finally {
      document.body.removeChild(temp);
    }
    return Promise.resolve();
  }

  function isOptedOutOfNavFeedback(el) {
    return Boolean(
      el
      && el instanceof Element
      && (
        el.hasAttribute('data-app-no-nav')
        || el.closest('[data-app-no-nav]')
      )
    );
  }

  function hasNonSelfTarget(el) {
    if (!el || !(el instanceof Element)) {
      return false;
    }
    const target = (el.getAttribute('target') || '').trim();
    return Boolean(target && target !== '_self');
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
    triggerEl = null,
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
      function restoreFocus() {
        if (!triggerEl || !(triggerEl instanceof HTMLElement) || !triggerEl.isConnected) {
          return;
        }
        try {
          triggerEl.focus({ preventScroll: true });
        } catch (e) {
          triggerEl.focus();
        }
      }
      function settle(value) {
        if (settled) return;
        settled = true;
        cleanup();
        if (!value) {
          restoreFocus();
        }
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

  function resetNavBusyState() {
    const body = document.body;
    const main = document.querySelector('main.app-main');
    const progress = document.getElementById('appNavProgress');
    body?.classList.remove('app-nav-busy');
    main?.removeAttribute('aria-busy');
    progress?.classList.remove('is-active');
    document.querySelectorAll('.app-nav-pending').forEach((el) => {
      el.classList.remove('app-nav-pending');
      el.removeAttribute('aria-disabled');
    });
  }

  function isPlainPrimaryActivation(event) {
    return !!event && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey;
  }

  function isHandledByBootstrap(link) {
    return Boolean(
      link.hasAttribute('data-bs-toggle')
      || link.hasAttribute('data-bs-dismiss')
      || link.getAttribute('role') === 'tab'
    );
  }

  function isEligibleNavigationLink(link, event) {
    if (!link || !isPlainPrimaryActivation(event)) {
      return false;
    }
    if (event.defaultPrevented || isOptedOutOfNavFeedback(link)) {
      return false;
    }
    if (link.hasAttribute('download') || link.hasAttribute('data-confirm') || isHandledByBootstrap(link)) {
      return false;
    }
    const rawHref = link.getAttribute('href') || '';
    if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:')) {
      return false;
    }
    if (hasNonSelfTarget(link) || /\bexternal\b/i.test(link.getAttribute('rel') || '')) {
      return false;
    }
    let url;
    try {
      url = new URL(link.href, window.location.href);
    } catch (e) {
      return false;
    }
    if (!/^https?:$/.test(url.protocol) || url.origin !== window.location.origin) {
      return false;
    }
    if (
      url.pathname === window.location.pathname
      && url.search === window.location.search
      && url.hash
    ) {
      return false;
    }
    return true;
  }

  function markNavBusy(trigger) {
    const body = document.body;
    const main = document.querySelector('main.app-main');
    const progress = document.getElementById('appNavProgress');
    body?.classList.add('app-nav-busy');
    main?.setAttribute('aria-busy', 'true');
    progress?.classList.add('is-active');
    if (trigger instanceof HTMLElement) {
      trigger.classList.add('app-nav-pending');
      trigger.setAttribute('aria-disabled', 'true');
    }
  }

  function appInitNavigationFeedback() {
    resetNavBusyState();
    window.addEventListener('load', resetNavBusyState, { once: true });
    window.addEventListener('pageshow', resetNavBusyState);

    document.addEventListener('click', (event) => {
      if (event.defaultPrevented) {
        return;
      }
      const target = event.target instanceof Element ? event.target : null;
      const link = target ? target.closest('a[href]') : null;
      if (!isEligibleNavigationLink(link, event)) {
        return;
      }
      markNavBusy(link);
    });

    document.addEventListener('submit', (event) => {
      const form = event.target instanceof HTMLFormElement ? event.target : null;
      if (!form || event.defaultPrevented) {
        return;
      }
      if (isOptedOutOfNavFeedback(form) || hasNonSelfTarget(form)) {
        return;
      }
      if (typeof form.checkValidity === 'function' && !form.noValidate && !form.checkValidity()) {
        if (window.appFocusFirstInvalid) {
          window.appFocusFirstInvalid(form, { toastMessage: '请检查必填项后再继续。' });
        }
        return;
      }
      const submitter = event.submitter instanceof HTMLElement ? event.submitter : null;
      if (submitter && (submitter.hasAttribute('data-bs-toggle') || isOptedOutOfNavFeedback(submitter))) {
        return;
      }
      markNavBusy(submitter || form);
    });
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
    const ok = await appConfirm({ ...getConfirmPayload(el), triggerEl: el });
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
  window.appAnnounce = appAnnounce;
  window.appSetButtonLoading = appSetButtonLoading;
  window.appCopyWithFeedback = appCopyWithFeedback;
  window.appFocusFirstInvalid = appFocusFirstInvalid;
  window.appGetCsrfToken = appGetCsrfToken;
  window.appCopyToClipboard = appCopyToClipboard;
  window.appConfirm = appConfirm;

  appInitNavigationFeedback();
  appInitModalAutoFocus();
  appAnnounceFirstMessage();
})();
