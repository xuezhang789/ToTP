import hashlib
import os
import re
from unittest import SkipTest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, Team, TeamAudit, TeamAsset, TeamInvitation, TeamMembership, TOTPEntry
from totp.utils import encrypt_str

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - exercised in environments without Playwright installed
    PlaywrightError = Exception
    sync_playwright = None


os.environ.setdefault("DJANGO_ALLOW_ASYNC_UNSAFE", "true")


BOOTSTRAP_STUB_JS = """
(() => {
  if (window.bootstrap) {
    return;
  }

  class BaseComponent {
    constructor(element, options = {}) {
      this._element = element;
      this._options = options;
    }

    static getOrCreateInstance(element, options = {}) {
      if (!this._instances) {
        this._instances = new WeakMap();
      }
      let instance = this._instances.get(element);
      if (!instance) {
        instance = new this(element, options);
        this._instances.set(element, instance);
      }
      return instance;
    }

    static getInstance(element) {
      return this._instances ? this._instances.get(element) || null : null;
    }
  }

  function emit(element, name, relatedTarget = null) {
    if (!element) {
      return;
    }
    const event = new CustomEvent(name, { bubbles: true, cancelable: true });
    Object.defineProperty(event, 'relatedTarget', { value: relatedTarget, configurable: true });
    element.dispatchEvent(event);
  }

  class Modal extends BaseComponent {
    show() {
      this._element.classList.add('show');
      this._element.style.display = 'block';
      this._element.removeAttribute('aria-hidden');
      emit(this._element, 'shown.bs.modal');
    }

    hide() {
      this._element.classList.remove('show');
      this._element.style.display = 'none';
      this._element.setAttribute('aria-hidden', 'true');
      window.setTimeout(() => emit(this._element, 'hidden.bs.modal'), 0);
    }
  }

  class Offcanvas extends BaseComponent {
    show() {
      this._element.classList.add('show');
      emit(this._element, 'shown.bs.offcanvas');
    }

    hide() {
      this._element.classList.remove('show');
      emit(this._element, 'hidden.bs.offcanvas');
    }
  }

  class Collapse extends BaseComponent {
    show() {
      this._element.classList.add('show');
      emit(this._element, 'shown.bs.collapse');
    }

    hide() {
      this._element.classList.remove('show');
      emit(this._element, 'hidden.bs.collapse');
    }
  }

  class Tab extends BaseComponent {
    show() {
      const trigger = this._element;
      const tablist = trigger.closest('[role="tablist"]');
      const previous = tablist ? tablist.querySelector('[data-bs-toggle="tab"].active') : null;

      if (tablist) {
        tablist.querySelectorAll('[data-bs-toggle="tab"]').forEach((item) => {
          item.classList.remove('active');
          item.setAttribute('aria-selected', 'false');
        });
      }

      const selector = trigger.getAttribute('data-bs-target') || trigger.getAttribute('href');
      const pane = selector ? document.querySelector(selector) : null;
      const container = pane ? pane.parentElement : null;
      if (container) {
        container.querySelectorAll('.tab-pane').forEach((item) => {
          item.classList.remove('show', 'active');
        });
      }

      trigger.classList.add('active');
      trigger.setAttribute('aria-selected', 'true');
      if (pane) {
        pane.classList.add('show', 'active');
      }
      emit(trigger, 'shown.bs.tab', previous);
    }
  }

  class Toast extends BaseComponent {
    show() {
      this._element.classList.add('show');
      emit(this._element, 'shown.bs.toast');
      const delay = Number(this._options.delay || 0);
      window.setTimeout(() => this.hide(), delay);
    }

    hide() {
      this._element.classList.remove('show');
      emit(this._element, 'hidden.bs.toast');
    }
  }

  window.bootstrap = { Modal, Offcanvas, Collapse, Tab, Toast };

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) {
      return;
    }

    const dismiss = target.closest('[data-bs-dismiss]');
    if (dismiss) {
      const kind = dismiss.getAttribute('data-bs-dismiss');
      const root = dismiss.closest(kind === 'toast' ? '.toast' : kind === 'offcanvas' ? '.offcanvas' : '.modal');
      if (!root) {
        return;
      }
      event.preventDefault();
      const component = kind === 'offcanvas'
        ? Offcanvas.getOrCreateInstance(root)
        : kind === 'toast'
          ? Toast.getOrCreateInstance(root)
          : Modal.getOrCreateInstance(root);
      component.hide();
      return;
    }

    const toggle = target.closest('[data-bs-toggle]');
    if (!toggle) {
      return;
    }

    const kind = toggle.getAttribute('data-bs-toggle');
    const selector = toggle.getAttribute('data-bs-target') || toggle.getAttribute('href');
    if (!selector) {
      return;
    }
    const element = document.querySelector(selector);
    if (!element) {
      return;
    }

    event.preventDefault();
    if (kind === 'modal') {
      Modal.getOrCreateInstance(element).show();
    } else if (kind === 'offcanvas') {
      Offcanvas.getOrCreateInstance(element).show();
    } else if (kind === 'tab') {
      Tab.getOrCreateInstance(toggle).show();
    }
  });
})();
"""


CLIPBOARD_STUB_JS = """
(() => {
  window.__copiedText = '';
  window.__copiedTexts = [];
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText(text) {
        const value = String(text ?? '');
        window.__copiedText = value;
        window.__copiedTexts.push(value);
        return Promise.resolve();
      },
    },
  });
})();
"""


class BrowserLiveServerTestCase(StaticLiveServerTestCase):
    host = "127.0.0.1"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if sync_playwright is None:
            raise SkipTest("Playwright is not installed.")
        try:
            cls._playwright = sync_playwright().start()
            cls._browser = cls._playwright.chromium.launch(headless=True)
        except PlaywrightError as exc:  # pragma: no cover - depends on browser install state
            raise SkipTest(f"Playwright browser is unavailable: {exc}") from exc
        cls.user_model = get_user_model()

    @classmethod
    def tearDownClass(cls):
        browser = getattr(cls, "_browser", None)
        playwright = getattr(cls, "_playwright", None)
        if browser is not None:
            browser.close()
        if playwright is not None:
            playwright.stop()
        super().tearDownClass()

    def setUp(self):
        self.context = self._new_context()
        self.page = self.context.new_page()
        self.page.set_default_timeout(10000)
        self.page.set_default_navigation_timeout(10000)

    def tearDown(self):
        self.context.close()

    def _new_context(self):
        context = self._browser.new_context(base_url=self.live_server_url)
        context.add_init_script(BOOTSTRAP_STUB_JS)
        context.add_init_script(CLIPBOARD_STUB_JS)
        context.route(re.compile(r"^https://accounts\.google\.com/.*$"), self._stub_external_resource)
        context.route(re.compile(r"^https://cdn\.jsdelivr\.net/.*$"), self._stub_external_resource)
        return context

    def _stub_external_resource(self, route):
        url = route.request.url
        content_type = "text/plain"
        body = ""
        if "accounts.google.com" in url or url.endswith(".js"):
            content_type = "application/javascript"
            body = "/* stubbed external script for browser tests */"
        elif url.endswith(".css"):
            content_type = "text/css"
        elif url.endswith(".woff2"):
            content_type = "font/woff2"
        route.fulfill(status=200, body=body, content_type=content_type)

    def _absolute_url(self, path: str) -> str:
        return f"{self.live_server_url}{path}"

    def _login_via_form(self, page, username: str, password: str):
        page.goto(self._absolute_url(reverse("accounts:login")), wait_until="domcontentloaded")
        page.fill("#loginUsername", username)
        page.fill("#loginPassword", password)
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.locator("form button[type='submit']").click()
        self.assertNotIn("/auth/login/", page.url)


class BrowserRegressionTests(BrowserLiveServerTestCase):
    @override_settings(
        EXTERNAL_TOOL_ENABLED=True,
        EXTERNAL_TOTP_RATE_LIMIT=3,
        EXTERNAL_TOTP_RATE_LIMIT_LONG=3,
        EXTERNAL_TOTP_RATE_WINDOW_SECONDS=60,
        EXTERNAL_TOTP_RATE_WINDOW_SECONDS_LONG=60,
    )
    def test_external_totp_browser_flow_blocks_abusive_requests(self):
        cache.clear()
        self.page.goto(
            self._absolute_url(reverse("totp:external_totp_tool")),
            wait_until="domcontentloaded",
        )
        statuses = self.page.evaluate(
            """
            async (url) => {
              const results = [];
              for (let i = 0; i < 4; i += 1) {
                const response = await fetch(url, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ secret: 'JBSWY3DPEHPK3PXP' }),
                });
                results.push(response.status);
              }
              return results;
            }
            """,
            self._absolute_url(reverse("totp:external_totp")),
        )
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3], 429)

    def test_share_link_modal_browser_flow_displays_copyable_url(self):
        user = self.user_model.objects.create_user(
            username="browser_share_owner",
            password="StrongPass123!",
            email="browser-share-owner@example.com",
        )
        entry = TOTPEntry.objects.create(
            user=user,
            name="Browser Share Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

        self._login_via_form(self.page, "browser_share_owner", "StrongPass123!")
        self.page.goto(self._absolute_url(reverse("totp:list")), wait_until="domcontentloaded")

        self.page.locator(f"button.share-link-btn[data-entry-id='{entry.id}']").click()
        self.page.locator("#shareLinkModal.show").wait_for()
        self.assertEqual(
            self.page.locator("#shareLinkEntryLabel").text_content().strip(),
            "Browser Share Entry",
        )

        self.page.select_option("#shareLinkDuration", "30")
        self.page.select_option("#shareLinkMaxViews", "4")
        self.page.fill("#shareLinkNote", "browser regression note")
        with self.page.expect_response(re.compile(r".*/totp/share/one-time/\d+/create/")):
            self.page.locator("#shareLinkSubmitBtn").click()

        self.page.locator("#shareLinkResult:not(.d-none)").wait_for()
        share_url = self.page.locator("#shareLinkUrl").input_value().strip()
        self.assertRegex(share_url, rf"^{re.escape(self.live_server_url)}/totp/link/")
        self.assertEqual(
            self.page.evaluate("() => window.__copiedText"),
            share_url,
        )
        self.assertIn("分享链接已生成", self.page.locator("#shareLinkResult").text_content())

        self.page.locator("#shareLinkCopyBtn").click()
        self.page.wait_for_function(
            "() => document.querySelector('#shareLinkCopyBtn').textContent.includes('已复制')"
        )
        self.assertGreaterEqual(self.page.evaluate("() => window.__copiedTexts.length"), 2)

    def test_expired_share_link_browser_flow_shows_invalid_state(self):
        owner = self.user_model.objects.create_user(
            username="browser_expired_owner",
            password="StrongPass123!",
            email="browser-expired-owner@example.com",
        )
        entry = TOTPEntry.objects.create(
            user=owner,
            name="Expired Browser Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        token = "expired-browser-token"
        OneTimeLink.objects.create(
            entry=entry,
            created_by=owner,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            expires_at=timezone.now() - timezone.timedelta(minutes=5),
            max_views=1,
        )

        response = self.page.goto(
            self._absolute_url(reverse("totp:one_time_view", args=[token])),
            wait_until="domcontentloaded",
        )

        self.assertIsNotNone(response)
        self.assertEqual(response.status, 410)
        body_text = self.page.locator("body").text_content()
        self.assertIn("链接已过期", body_text)
        self.assertNotIn("当前验证码", body_text)

    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_onetap_browser_flow_creates_session(self, verify_mock):
        verify_mock.return_value = {
            "email": "browser-google@example.com",
            "email_verified": True,
            "name": "Browser Google User",
            "sub": "browser-google-sub",
        }

        self.page.goto(self._absolute_url(reverse("accounts:login")), wait_until="domcontentloaded")
        with self.page.expect_navigation(wait_until="domcontentloaded"):
            self.page.evaluate(
                "(credential) => onetapLogin(credential)",
                "fake-google-credential",
            )

        self.page.goto(self._absolute_url(reverse("accounts:profile")), wait_until="domcontentloaded")
        self.assertEqual(
            self.page.locator("#id_email").input_value().strip(),
            "browser-google@example.com",
        )

    def test_logout_browser_flow_confirms_and_returns_to_login(self):
        self.user_model.objects.create_user(
            username="browser_logout_user",
            password="StrongPass123!",
            email="browser-logout@example.com",
        )

        self._login_via_form(self.page, "browser_logout_user", "StrongPass123!")
        self.page.locator("#navbarLogoutButton").click()
        self.page.locator("#appConfirmModal.show").wait_for()

        with self.page.expect_navigation(wait_until="domcontentloaded"):
            self.page.locator("#appConfirmOkBtn").click()

        self.assertIn("/auth/login/", self.page.url)
        self.assertIn("你已安全退出", self.page.locator("body").text_content())

    def test_prevented_and_download_links_do_not_trigger_nav_busy_feedback(self):
        self.page.goto(self._absolute_url(reverse("accounts:login")), wait_until="domcontentloaded")
        self.page.evaluate(
            """
            () => {
              const prevented = document.createElement('a');
              prevented.id = 'prevented-link';
              prevented.href = '/should-not-navigate/';
              prevented.textContent = 'prevented';
              prevented.addEventListener('click', (event) => event.preventDefault());
              document.body.appendChild(prevented);

              const skipped = document.createElement('a');
              skipped.id = 'download-link';
              skipped.href = '/download-like/';
              skipped.textContent = 'download';
              skipped.setAttribute('data-app-no-nav', '1');
              skipped.addEventListener('click', (event) => event.preventDefault());
              document.body.appendChild(skipped);
            }
            """
        )

        self.page.locator("#prevented-link").click()
        self.page.wait_for_timeout(50)
        self.assertFalse(self.page.evaluate("() => document.body.classList.contains('app-nav-busy')"))

        self.page.locator("#download-link").click()
        self.page.wait_for_timeout(50)
        self.assertFalse(self.page.evaluate("() => document.body.classList.contains('app-nav-busy')"))

    def test_member_removal_browser_flow_revokes_member_access(self):
        owner = self.user_model.objects.create_user(
            username="browser_owner",
            password="StrongPass123!",
            email="browser-owner@example.com",
        )
        member = self.user_model.objects.create_user(
            username="browser_member",
            password="StrongPass123!",
            email="browser-member@example.com",
        )
        team = Team.objects.create(owner=owner, name="Browser Team")
        TeamMembership.objects.create(team=team, user=owner, role=TeamMembership.Role.OWNER)
        member_membership = TeamMembership.objects.create(
            team=team,
            user=member,
            role=TeamMembership.Role.ADMIN,
        )
        asset = TeamAsset.objects.create(team=team, name="Browser Asset", description="")
        asset.owners.add(member)
        asset.watchers.add(member)
        entry = TOTPEntry.objects.create(
            user=owner,
            team=team,
            name="Browser Shared Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        OneTimeLink.objects.create(
            entry=entry,
            created_by=member,
            token_hash="c" * 64,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            max_views=3,
        )

        member_context = self._new_context()
        member_page = member_context.new_page()
        member_page.set_default_timeout(10000)
        member_page.set_default_navigation_timeout(10000)

        try:
            self._login_via_form(self.page, "browser_owner", "StrongPass123!")
            self._login_via_form(member_page, "browser_member", "StrongPass123!")

            member_page.goto(
                self._absolute_url(reverse("totp:one_time_audit")),
                wait_until="domcontentloaded",
            )
            self.assertIn("Browser Shared Entry", member_page.locator("body").text_content())

            self.page.goto(
                self._absolute_url(reverse("totp:team_home", args=[team.id])),
                wait_until="domcontentloaded",
            )
            self.page.locator(f"#teamTab-{team.id}-members").click()
            members_pane = self.page.locator(f"#teamPane-{team.id}-members")
            members_pane.wait_for()
            self.page.wait_for_function(
                "([selector, username]) => {"
                "  const pane = document.querySelector(selector);"
                "  return !!pane && pane.textContent.includes(username);"
                "}",
                arg=[f"#teamPane-{team.id}-members", "browser_member"],
            )

            remove_button = self.page.locator(
                (
                    f"#teamPane-{team.id}-members "
                    f"form[action$='/teams/{team.id}/members/{member_membership.id}/remove/'] "
                    "button[data-confirm-title='移除成员']"
                )
            )
            remove_button.click(force=True)
            self.page.locator("#appConfirmModal.show").wait_for()
            with self.page.expect_navigation(wait_until="domcontentloaded"):
                self.page.locator("#appConfirmOkBtn").click()

            self.assertIn("已被移出团队", self.page.locator("body").text_content())

            member_page.goto(
                self._absolute_url(reverse("totp:one_time_audit")),
                wait_until="domcontentloaded",
            )
            self.assertNotIn("Browser Shared Entry", member_page.locator("body").text_content())

            self.page.goto(
                self._absolute_url(reverse("totp:team_asset_detail", args=[team.id, asset.id])),
                wait_until="domcontentloaded",
            )
            self.assertNotIn("browser_member", self.page.locator("body").text_content())
        finally:
            member_context.close()

    def test_team_risk_panel_browser_flow_loads_and_opens_members_tab(self):
        owner = self.user_model.objects.create_user(
            username="browser_risk_owner",
            password="StrongPass123!",
            email="browser-risk-owner@example.com",
        )
        invitee = self.user_model.objects.create_user(
            username="browser_risk_invitee",
            password="StrongPass123!",
            email="browser-risk-invitee@example.com",
        )
        target = self.user_model.objects.create_user(
            username="browser_risk_target",
            password="StrongPass123!",
            email="browser-risk-target@example.com",
        )
        team = Team.objects.create(owner=owner, name="Browser Risk Team")
        TeamMembership.objects.create(team=team, user=owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=team, user=target, role=TeamMembership.Role.MEMBER)
        TeamInvitation.objects.create(
            team=team,
            inviter=owner,
            invitee=invitee,
            role=TeamMembership.Role.MEMBER,
        )
        entry = TOTPEntry.objects.create(
            user=owner,
            team=team,
            name="Browser Risk Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=owner,
            team=team,
            name="Browser Unassigned Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        OneTimeLink.objects.create(
            entry=entry,
            created_by=owner,
            token_hash="d" * 64,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            max_views=3,
            last_viewed_at=timezone.now(),
        )
        TeamAudit.objects.create(team=team, actor=owner, action=TeamAudit.Action.LINKS_REVOKED_ALL)
        TeamAudit.objects.create(
            team=team,
            actor=owner,
            action=TeamAudit.Action.MEMBER_ROLE_CHANGED,
            target_user=target,
        )

        self._login_via_form(self.page, "browser_risk_owner", "StrongPass123!")
        self.page.goto(
            self._absolute_url(reverse("totp:team_home", args=[team.id])),
            wait_until="domcontentloaded",
        )

        sidebar = self.page.locator("#teamSidebarPanel")
        sidebar.wait_for()
        self.page.wait_for_function(
            "() => {"
            "  const panel = document.querySelector('#teamSidebarPanel');"
            "  return !!panel && panel.textContent.includes('高风险');"
            "}"
        )
        sidebar_text = sidebar.text_content()
        self.assertIn("高风险", sidebar_text)
        self.assertIn("分享链接", sidebar_text)
        self.assertIn("邀请", sidebar_text)
        self.assertIn("资产", sidebar_text)

        self.page.locator("#teamSidebarPanel button[data-open-team-tab='members']").first.click()
        self.page.wait_for_function(
            "(teamId) => {"
            "  const tab = document.querySelector(`#teamTab-${teamId}-members`);"
            "  const pane = document.querySelector(`#teamPane-${teamId}-members`);"
            "  return !!tab && tab.classList.contains('active')"
            "    && !!pane && pane.textContent.includes('browser_risk_target');"
            "}",
            arg=team.id,
        )
        self.assertEqual(
            self.page.locator(f"#teamTab-{team.id}-members").get_attribute("aria-selected"),
            "true",
        )
