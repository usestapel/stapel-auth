"""``error.429.rate_limit`` on the wire, against the committed contract.

A native client's suite reported the code unbound on ``POST /email/request/``
and two params missing from ``errors.json``. The binding was already in the
profile-2 contract (``x-stapel-errors`` on the 429 response; the client routed
429 through its transport family before its domain mapping); the params were
not. This drives the second request inside the cooldown and holds the answer
to both: the code is bound on that operation, and every param it carries is
documented.
"""
import json
from pathlib import Path

import pytest
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

DOCS = Path(__file__).resolve().parent.parent / "docs"


def _errors():
    return {e["code"]: e for e in json.loads((DOCS / "errors.json").read_text())}


@pytest.mark.django_db
@override_settings(URL_PREFIX="")
@pytest.mark.parametrize("url_name,body", [
    ("email_request", {"email": "rl@example.com"}),
    ("phone_request", {"phone": "+12025550147"}),
])
def test_rate_limit_answer_is_bound_and_documented(url_name, body):
    """The second request inside the cooldown, on the wire."""
    cache.clear()
    client = APIClient()
    first = client.post(reverse(url_name), body, format="json")
    assert first.status_code == 200, first.content
    second = client.post(reverse(url_name), body, format="json")
    assert second.status_code == 429, second.content
    answer = second.json()
    assert answer["localizable_error"] == "error.429.rate_limit"
    assert set(answer["params"]) <= set(_errors()["error.429.rate_limit"]["params"])
    v2 = json.loads((DOCS / "schema.v2.json").read_text())
    path = "/auth/api/v1" + reverse(url_name).split("/v1", 1)[1]
    bound = v2["paths"][path]["post"]["responses"]["429"]["x-stapel-errors"]
    assert "error.429.rate_limit" in bound

