from __future__ import annotations

import secrets

from django.conf import settings
from django.core import signing
from django.utils import timezone

IMPORT_PREVIEW_SESSION_KEY = "totp_import_previews_v1"
IMPORT_PREVIEW_SIGNING_SALT = "totp.import.preview"
DEFAULT_IMPORT_PREVIEW_TTL_SECONDS = 15 * 60
MAX_STORED_IMPORT_PREVIEWS = 5


def import_preview_ttl_seconds() -> int:
    return int(
        getattr(
            settings,
            "IMPORT_PREVIEW_TTL_SECONDS",
            DEFAULT_IMPORT_PREVIEW_TTL_SECONDS,
        )
        or DEFAULT_IMPORT_PREVIEW_TTL_SECONDS
    )


def _load_bucket(session) -> tuple[dict[str, dict], bool]:
    raw = session.get(IMPORT_PREVIEW_SESSION_KEY)
    bucket = raw if isinstance(raw, dict) else {}
    now_ts = int(timezone.now().timestamp())
    ttl_seconds = import_preview_ttl_seconds()
    changed = not isinstance(raw, dict)
    stale_keys = [
        preview_id
        for preview_id, payload in bucket.items()
        if not isinstance(payload, dict)
        or now_ts - int(payload.get("created_at") or 0) > ttl_seconds
    ]
    for key in stale_keys:
        bucket.pop(key, None)
        changed = True
    return bucket, changed


def _save_bucket(session, bucket: dict[str, dict]):
    session[IMPORT_PREVIEW_SESSION_KEY] = bucket
    session.modified = True


def store_import_preview(
    request,
    *,
    space: str,
    target_label: str,
    asset_id: str,
    entries: list[dict],
):
    bucket, changed = _load_bucket(request.session)
    if changed:
        _save_bucket(request.session, bucket)

    preview_id = secrets.token_urlsafe(18)
    bucket[preview_id] = {
        "user_id": request.user.pk,
        "space": space,
        "target_label": target_label,
        "asset_id": str(asset_id or ""),
        "entries": entries,
        "created_at": int(timezone.now().timestamp()),
    }

    if len(bucket) > MAX_STORED_IMPORT_PREVIEWS:
        ordered = sorted(
            bucket.items(),
            key=lambda item: int(item[1].get("created_at") or 0),
        )
        for stale_id, _payload in ordered[:-MAX_STORED_IMPORT_PREVIEWS]:
            bucket.pop(stale_id, None)

    _save_bucket(request.session, bucket)
    return signing.dumps(
        {"preview_id": preview_id, "uid": request.user.pk},
        salt=IMPORT_PREVIEW_SIGNING_SALT,
    )


def load_import_preview(request, token: str) -> dict:
    try:
        payload = signing.loads(
            token,
            salt=IMPORT_PREVIEW_SIGNING_SALT,
            max_age=import_preview_ttl_seconds(),
        )
    except signing.BadSignature as exc:
        raise ValueError("preview_expired") from exc

    if payload.get("uid") != request.user.pk:
        raise ValueError("preview_invalid")

    bucket, changed = _load_bucket(request.session)
    preview_id = payload.get("preview_id") or ""
    preview = bucket.get(preview_id)
    if changed:
        _save_bucket(request.session, bucket)
    if not isinstance(preview, dict):
        raise ValueError("preview_expired")
    if preview.get("user_id") != request.user.pk:
        raise ValueError("preview_invalid")
    return preview


def discard_import_preview(request, token: str):
    try:
        payload = signing.loads(
            token,
            salt=IMPORT_PREVIEW_SIGNING_SALT,
            max_age=import_preview_ttl_seconds(),
        )
    except signing.BadSignature:
        return

    bucket, changed = _load_bucket(request.session)
    preview_id = payload.get("preview_id") or ""
    if preview_id in bucket:
        del bucket[preview_id]
        changed = True
    if changed:
        _save_bucket(request.session, bucket)
