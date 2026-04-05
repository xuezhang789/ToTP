(() => {
  const bootstrap = window.bootstrap;
  if (!bootstrap) {
    return;
  }

  const toggleBtn = document.getElementById('toggleTeamDetailsBtn');
  const renameModalEl = document.getElementById('renameTeamModal');
  const renameForm = document.getElementById('renameTeamForm');
  const renameInput = document.getElementById('renameTeamNameInput');
  const actionsOffcanvasEl = document.getElementById('teamActionsOffcanvas');
  const actionsOffcanvasBody = document.getElementById('teamActionsOffcanvasBody');
  const actionsOffcanvasTitle = document.getElementById('teamActionsOffcanvasLabel');

  function getAllCollapses() {
    return Array.from(document.querySelectorAll('.team-details-collapse'));
  }

  function isShown(el) {
    return el.classList.contains('show');
  }

  function updateGlobalToggle() {
    if (!toggleBtn) {
      return;
    }
    const items = getAllCollapses();
    if (!items.length) {
      toggleBtn.disabled = true;
      return;
    }
    const allShown = items.every((el) => isShown(el));
    toggleBtn.textContent = allShown ? '全部收起' : '全部展开';
    toggleBtn.setAttribute('aria-pressed', allShown ? 'true' : 'false');
    toggleBtn.disabled = false;
  }

  function updateDetailsToggleForCollapse(collapseEl) {
    const id = collapseEl?.id || '';
    if (!id) {
      return;
    }
    const btn = document.querySelector(`[aria-controls="${CSS.escape(id)}"]`);
    if (!btn) {
      return;
    }
    const labelEl = btn.querySelector('[data-team-details-toggle]');
    if (!labelEl) {
      return;
    }
    const expanded = isShown(collapseEl);
    const collapsedText = labelEl.dataset.collapsedText || '展开详情';
    const expandedText = labelEl.dataset.expandedText || '收起详情';
    labelEl.textContent = expanded ? expandedText : collapsedText;
    btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    const icon = btn.querySelector('i');
    if (icon) {
      icon.classList.toggle('bi-chevron-down', !expanded);
      icon.classList.toggle('bi-chevron-up', expanded);
    }
  }

  function setOffcanvasLoading(titleText) {
    if (actionsOffcanvasTitle && titleText) {
      actionsOffcanvasTitle.textContent = titleText;
    }
    if (actionsOffcanvasBody) {
      actionsOffcanvasBody.innerHTML = '<div class="text-muted small">加载中…</div>';
    }
  }

  function loadOffcanvasPanel({ teamId, teamName, url }) {
    if (!actionsOffcanvasEl || !actionsOffcanvasBody || !url) {
      return;
    }
    setOffcanvasLoading(teamName ? `团队操作 · ${teamName}` : '团队操作');
    const panelUrl = new URL(url, window.location.origin);
    panelUrl.searchParams.set(
      'context',
      document.getElementById('teamSidebarPanel') ? 'home' : 'teams',
    );
    fetch(panelUrl.toString(), { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.text();
      })
      .then((html) => {
        actionsOffcanvasBody.innerHTML = html;
        actionsOffcanvasBody.dataset.teamId = String(teamId || '');
      })
      .catch(() => {
        actionsOffcanvasBody.innerHTML = '<div class="text-muted small">加载失败，请稍后重试。</div>';
      });
  }

  function ensureTeamDetailsOpen(teamId) {
    const collapseEl = document.getElementById(`teamDetails-${teamId}`);
    if (!collapseEl) {
      return null;
    }
    const instance = bootstrap.Collapse.getOrCreateInstance(collapseEl, { toggle: false });
    instance.show();
    return collapseEl;
  }

  function showTeamTab(teamId, tabKey) {
    const btn = document.getElementById(`teamTab-${teamId}-${tabKey}`);
    if (!btn) {
      return;
    }
    const tab = bootstrap.Tab.getOrCreateInstance(btn);
    tab.show();
  }

  toggleBtn?.addEventListener('click', () => {
    const items = getAllCollapses();
    if (!items.length) {
      return;
    }
    const allShown = items.every((el) => isShown(el));
    const shouldExpand = !allShown;
    items.forEach((el) => {
      const instance = bootstrap.Collapse.getOrCreateInstance(el, { toggle: false });
      if (shouldExpand) {
        instance.show();
      } else {
        instance.hide();
      }
    });
    updateGlobalToggle();
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

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const btn = target.closest('[data-team-actions-trigger]');
    if (!btn) {
      return;
    }
    const teamId = btn.getAttribute('data-team-id') || '';
    const teamName = btn.getAttribute('data-team-name') || '';
    const url = btn.getAttribute('data-team-panel-url') || '';
    loadOffcanvasPanel({ teamId, teamName, url });
  });

  renameModalEl?.addEventListener('shown.bs.modal', () => {
    if (window.appFocusElement) {
      window.appFocusElement(renameInput, { select: true });
      return;
    }
    renameInput?.focus();
    renameInput?.select();
  });

  function notify(teamId, variant, message) {
    const el = document.getElementById(`teamInlineAlert-${teamId}`);
    if (window.appNotify) {
      window.appNotify({ alertEl: el, variant, message });
      return;
    }
    if (window.appInlineAlert) {
      window.appInlineAlert(el, variant, message);
    }
  }

  function renderPaneLoading(pane) {
    if (!pane) {
      return;
    }
    pane.innerHTML = '<div class="text-muted small py-4">加载中…</div>';
  }

  function loadTabPane(pane) {
    if (!pane || pane.dataset.loaded === '1') {
      return;
    }
    const url = pane.dataset.loadUrl || '';
    if (!url) {
      return;
    }
    pane.dataset.loaded = '1';
    renderPaneLoading(pane);
    fetch(url, { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.text();
      })
      .then((html) => {
        pane.innerHTML = html;
      })
      .catch(() => {
        pane.dataset.loaded = '0';
        pane.innerHTML = '<div class="text-muted small py-4">加载失败，请稍后重试。</div>';
      });
  }

  function loadIntoPane(pane, url) {
    if (!pane || !url) {
      return;
    }
    renderPaneLoading(pane);
    fetch(url, { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.text();
      })
      .then((html) => {
        pane.dataset.loaded = '1';
        pane.innerHTML = html;
      })
      .catch(() => {
        pane.innerHTML = '<div class="text-muted small py-4">加载失败，请稍后重试。</div>';
      });
  }

  function findMembersPane(teamId) {
    const pane = document.getElementById(`teamPane-${teamId}-members`);
    if (!(pane instanceof HTMLElement)) {
      return null;
    }
    return pane;
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

  document.addEventListener('submit', (event) => {
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    if (!form) return;
    if (!form.hasAttribute('data-team-members-search')) {
      return;
    }
    event.preventDefault();
    const teamId = form.getAttribute('data-team-id') || '';
    const baseUrl = form.getAttribute('data-load-url') || '';
    if (!teamId || !baseUrl) {
      return;
    }
    const params = new URLSearchParams(new FormData(form));
    const url = `${baseUrl}?${params.toString()}`;
    const pane = findMembersPane(teamId);
    loadIntoPane(pane, url);
  });

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const resetBtn = target.closest('[data-team-members-reset]');
    if (!resetBtn) {
      return;
    }
    const form = resetBtn.closest('form[data-team-members-search]');
    if (!form) {
      return;
    }
    const teamId = form.getAttribute('data-team-id') || '';
    const baseUrl = form.getAttribute('data-load-url') || '';
    if (!teamId || !baseUrl) {
      return;
    }
    const input = form.querySelector('input[name="q"]');
    if (input) {
      input.value = '';
    }
    const url = `${baseUrl}?q=`;
    const pane = findMembersPane(teamId);
    loadIntoPane(pane, url);
  });

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const link = target.closest('a[data-team-fragment-link]');
    if (!link) {
      return;
    }
    const teamId = link.getAttribute('data-team-id') || '';
    const href = link.getAttribute('href') || '';
    if (!teamId || !href) {
      return;
    }
    const pane = findMembersPane(teamId);
    if (!pane) {
      return;
    }
    event.preventDefault();
    loadIntoPane(pane, href);
  });

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const showRevokeBtn = target.closest('[data-show-revoke-summary]');
    if (showRevokeBtn) {
      const scope =
        showRevokeBtn.closest('#teamActionsOffcanvasBody') ||
        showRevokeBtn.closest('#teamSidebarPanel') ||
        showRevokeBtn.parentElement;
      const summary = scope?.querySelector?.('[data-revoke-summary]') || null;
      if (summary) {
        summary.classList.remove('d-none');
        summary.scrollIntoView({ block: 'nearest' });
      }
      return;
    }

    const hideRevokeBtn = target.closest('[data-hide-revoke-summary]');
    if (hideRevokeBtn) {
      const scope =
        hideRevokeBtn.closest('#teamActionsOffcanvasBody') ||
        hideRevokeBtn.closest('#teamSidebarPanel') ||
        hideRevokeBtn.parentElement;
      const summary = scope?.querySelector?.('[data-revoke-summary]') || null;
      if (summary) {
        summary.classList.add('d-none');
      }
      return;
    }

    const btn = target.closest('[data-open-team-tab]');
    if (!btn) {
      return;
    }
    const tabKey = btn.getAttribute('data-open-team-tab') || '';
    const teamId =
      btn.getAttribute('data-team-id') ||
      actionsOffcanvasBody?.dataset.teamId ||
      '';
    if (!teamId || !tabKey) {
      return;
    }
    ensureTeamDetailsOpen(teamId);
    showTeamTab(teamId, tabKey);
    if (btn.closest('#teamActionsOffcanvas')) {
      const instance = bootstrap.Offcanvas.getInstance(actionsOffcanvasEl);
      instance?.hide();
    }
  });

  const collapses = getAllCollapses();
  collapses.forEach((el) => {
    updateDetailsToggleForCollapse(el);
    el.addEventListener('shown.bs.collapse', () => {
      updateDetailsToggleForCollapse(el);
      updateGlobalToggle();
    });
    el.addEventListener('hidden.bs.collapse', () => {
      updateDetailsToggleForCollapse(el);
      updateGlobalToggle();
    });
  });
  updateGlobalToggle();

  const sidebarPanel = document.getElementById('teamSidebarPanel');
  if (sidebarPanel) {
    const url = sidebarPanel.getAttribute('data-team-panel-url') || '';
    if (url) {
      sidebarPanel.innerHTML = '<div class="text-muted small">加载中…</div>';
      const panelUrl = new URL(url, window.location.origin);
      panelUrl.searchParams.set('context', 'home');
      fetch(panelUrl.toString(), { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
        .then((resp) => {
          if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
          }
          return resp.text();
        })
        .then((html) => {
          sidebarPanel.innerHTML = html;
        })
        .catch(() => {
          sidebarPanel.innerHTML = '<div class="text-muted small">加载失败，请稍后重试。</div>';
        });
    }
  }

  const tabParam = new URLSearchParams(window.location.search).get('tab') || '';
  if (tabParam && ['overview', 'members', 'assets', 'security', 'audit'].includes(tabParam)) {
    const tabsEl = document.querySelector('[id^="teamTabs-"]');
    if (tabsEl) {
      const raw = tabsEl.getAttribute('id') || '';
      const teamId = raw.replace('teamTabs-', '');
      if (teamId) {
        showTeamTab(teamId, tabParam);
      }
    }
  }

  document.querySelectorAll('button[data-bs-toggle="tab"]').forEach((btn) => {
    btn.addEventListener('shown.bs.tab', (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      const selector = target.getAttribute('data-bs-target') || '';
      if (!selector) return;
      const pane = document.querySelector(selector);
      if (!(pane instanceof HTMLElement)) return;
      if (!pane.dataset.teamTabPane) return;
      loadTabPane(pane);
    });
  });
})();
