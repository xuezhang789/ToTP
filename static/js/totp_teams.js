(() => {
  const bootstrap = window.bootstrap;
  if (!bootstrap) {
    return;
  }

  const toggleBtn = document.getElementById('toggleTeamDetailsBtn');
  const renameModalEl = document.getElementById('renameTeamModal');
  const renameForm = document.getElementById('renameTeamForm');
  const renameInput = document.getElementById('renameTeamNameInput');

  function getAllCollapses() {
    return Array.from(document.querySelectorAll('.team-details-collapse'));
  }

  function isShown(el) {
    return el.classList.contains('show');
  }

  toggleBtn?.addEventListener('click', () => {
    const items = getAllCollapses();
    if (!items.length) {
      return;
    }
    const shouldExpand = items.some((el) => !isShown(el));
    items.forEach((el) => {
      const instance = bootstrap.Collapse.getOrCreateInstance(el, { toggle: false });
      if (shouldExpand) {
        instance.show();
      } else {
        instance.hide();
      }
    });
  });

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const btn = target.closest('[data-team-rename-trigger]');
    if (!btn || !renameModalEl || !renameForm || !renameInput) {
      return;
    }
    const url = btn.getAttribute('data-team-rename-url') || '';
    const name = btn.getAttribute('data-team-name') || '';
    if (!url) {
      return;
    }
    renameForm.action = url;
    renameInput.value = name;
    const modal = bootstrap.Modal.getOrCreateInstance(renameModalEl);
    modal.show();
  });

  renameModalEl?.addEventListener('shown.bs.modal', () => {
    renameInput?.focus({ preventScroll: true });
    renameInput?.select();
  });

  function notify(teamId, variant, message) {
    const el = document.getElementById(`teamInlineAlert-${teamId}`);
    if (window.appNotify) {
      window.appNotify({ alertEl: el, variant, message });
      return;
    }
    if (el) {
      el.textContent = message;
      el.classList.toggle('d-none', !message);
    }
  }

  async function postForm(form) {
    const csrf = window.appGetCsrfToken ? window.appGetCsrfToken() : '';
    const resp = await fetch(form.action, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'fetch',
        'X-CSRFToken': csrf,
      },
      body: new FormData(form),
      credentials: 'same-origin',
    });
    if (resp.redirected && resp.url) {
      if (resp.url.includes('/auth/login') || resp.url.includes('/auth/reauth')) {
        window.location.href = resp.url;
        return null;
      }
    }
    return resp;
  }

  function updatePendingInvites(teamId, delta) {
    const countEl = document.getElementById(`pendingCount-${teamId}`);
    const badgeEl = document.getElementById(`pendingCountBadge-${teamId}`);
    const alertEl = document.getElementById(`pendingInvitesAlert-${teamId}`);
    const textEl = document.getElementById(`pendingInvitesCountText-${teamId}`);
    const current = countEl ? Number(countEl.textContent || '0') : 0;
    const next = Math.max(0, current + delta);
    if (countEl) countEl.textContent = String(next);
    if (textEl) textEl.textContent = String(next);
    if (badgeEl) badgeEl.classList.toggle('d-none', next === 0);
    if (alertEl) alertEl.classList.toggle('d-none', next === 0);
  }

  function roleLabel(role) {
    if (role === 'admin') return '管理员';
    if (role === 'member') return '成员';
    if (role === 'owner') return '所有者';
    return role;
  }

  function updateMemberRole(row, role) {
    if (!row) return;
    row.dataset.role = role;
    const badge = row.querySelector('.js-role-badge');
    if (badge) {
      badge.textContent = roleLabel(role);
      badge.classList.remove('bg-dark', 'bg-primary', 'bg-secondary');
      badge.classList.add(role === 'owner' ? 'bg-dark' : role === 'admin' ? 'bg-primary' : 'bg-secondary');
    }
    row.querySelectorAll('button.js-member-role').forEach((btn) => {
      const targetRole = btn.dataset.targetRole;
      btn.disabled = targetRole === role;
    });
  }

  document.addEventListener('submit', (event) => {
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    if (!form) return;

    if (form.classList.contains('js-invite-cancel')) {
      event.preventDefault();
      const teamId = form.dataset.teamId;
      if (!teamId) return;
      notify(teamId, 'info', '正在取消邀请…');
      postForm(form)
        .then((resp) => {
          if (!resp) return;
          if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
          }
          const badge = form.closest('[data-invite-id]');
          badge?.remove();
          updatePendingInvites(teamId, -1);
          notify(teamId, 'success', '已取消邀请');
        })
        .catch(() => {
          notify(teamId, 'danger', '取消失败，请稍后重试。');
        });
      return;
    }

    const roleBtn = form.querySelector('button.js-member-role');
    if (roleBtn) {
      event.preventDefault();
      const teamId = roleBtn.dataset.teamId;
      const targetRole = roleBtn.dataset.targetRole;
      const row = form.closest('tr[data-member-id]');
      if (!teamId || !targetRole || !row) return;
      notify(teamId, 'info', '正在更新角色…');
      roleBtn.disabled = true;
      postForm(form)
        .then((resp) => {
          if (!resp) return;
          if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
          }
          updateMemberRole(row, targetRole);
          notify(teamId, 'success', '角色已更新');
        })
        .catch(() => {
          roleBtn.disabled = false;
          notify(teamId, 'danger', '更新失败，请稍后重试。');
        });
    }
  });
})();
