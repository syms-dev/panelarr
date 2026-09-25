from __future__ import annotations

import httpx

from backend.services.config import qbittorrent_login_succeeded


def _response(
    *,
    status_code: int = 200,
    text: str = "",
    set_cookie: str | None = None,
) -> httpx.Response:
    headers = {}
    if set_cookie is not None:
        headers["set-cookie"] = set_cookie
    request = httpx.Request("POST", "http://qbittorrent:8080/api/v2/auth/login")
    return httpx.Response(
        status_code,
        text=text,
        headers=headers,
        request=request,
    )


def test_qbittorrent4_ok_body() -> None:
    assert qbittorrent_login_succeeded(_response(status_code=200, text="Ok."))


def test_qbittorrent4_ok_body_without_dot() -> None:
    assert qbittorrent_login_succeeded(_response(status_code=200, text="Ok"))


def test_qbittorrent5_empty_204_with_sid_cookie() -> None:
    resp = _response(
        status_code=204,
        text="",
        set_cookie="SID=abc123; HttpOnly; path=/",
    )
    assert bool(resp.cookies)
    assert qbittorrent_login_succeeded(resp)


def test_qbittorrent5_failed_login_has_no_cookie() -> None:
    resp = _response(status_code=204, text="")
    assert not resp.cookies
    assert not qbittorrent_login_succeeded(resp)


def test_qbittorrent_fails_body_is_rejected() -> None:
    assert not qbittorrent_login_succeeded(_response(status_code=200, text="Fails."))
