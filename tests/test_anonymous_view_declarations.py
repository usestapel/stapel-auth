"""Every view a guest session passes must say whether that was meant.

A guest is not ``AnonymousUser``: it is a user row with ``is_anonymous=True``
that PASSES ``IsAuthenticated``. ``stapel_core.adoption`` E001/W002 read a
view as having taken a position as soon as any second permission class stands
beside ``IsAuthenticated`` — and ``DenyEnrollOnly``, the companion on every
account-facing view in this module, asks about enrolment, not identity. A
guest passes it. So seven views admitted guests with nothing in their source
saying so, and the static check was silent on all seven.

This is the runtime sibling, the shape stapel-gdpr runs against its own URL
conf: build the whole gate stack, call it twice — once with ``AnonymousUser``,
once with a guest — and demand a declaration from every view that refuses the
first and admits the second.
"""
import pytest


def _module_views(patterns):
    """Every view class this module routes to, each one once."""
    seen = {}
    for pattern in patterns:
        for entry in getattr(pattern, "url_patterns", [pattern]):
            view_cls = getattr(getattr(entry, "callback", None), "cls", None)
            if view_cls is None:
                continue
            if not view_cls.__module__.startswith("stapel_auth"):
                continue  # generated schema views are not ours to declare for
            seen.setdefault(view_cls.__name__, view_cls)
    return [seen[name] for name in sorted(seen)]


def _admits(rf, view_cls, principal):
    """Does the whole gate stack let *principal* through — or refuse to say?

    ``None`` when a gate RAISES while being probed (it queries the database,
    calls a seam, reads a request attribute this probe does not fake). A
    guess dressed as a verdict is worse than no verdict, so such a view is
    skipped rather than reported.
    """
    request = rf.get("/")
    request.user = principal
    view = view_cls()
    try:
        return all(
            gate().has_permission(request, view)
            for gate in view_cls.permission_classes
        )
    except Exception:
        return None


@pytest.mark.django_db
class TestNoViewLeavesTheGuestQuestionOpen:
    @pytest.fixture
    def guest(self):
        from django.contrib.auth import get_user_model

        return get_user_model().create_anonymous_user()

    def test_every_view_a_guest_passes_says_so(self, rf, guest):
        from django.contrib.auth.models import AnonymousUser
        from stapel_core.django.api.permissions import (
            ANONYMOUS_DECLARATION_ATTR,
            ANONYMOUS_DECLARATIONS,
        )

        from stapel_auth import urls_v1

        undeclared = []
        for view_cls in _module_views(urls_v1.urlpatterns):
            if _admits(rf, view_cls, AnonymousUser()) is not False:
                continue  # public, or no verdict at all
            if _admits(rf, view_cls, guest) is not True:
                continue
            declaration = getattr(view_cls, ANONYMOUS_DECLARATION_ATTR, None)
            if declaration not in ANONYMOUS_DECLARATIONS:
                undeclared.append(view_cls.__name__)
        assert undeclared == [], (
            "a guest session passes the gate of these views and nothing in "
            f"their source says whether that was meant: {undeclared}"
        )

    def test_the_views_a_guest_is_meant_to_use_still_admit_it(self, rf, guest):
        """The declaration is a statement about behaviour, so read it back."""
        from stapel_auth.oauth.views import OAuthLinkViewSet
        from stapel_auth.security.views import AuditLogViewSet, SecurityStatusViewSet
        from stapel_auth.sessions.views import SessionViewSet
        from stapel_auth.verification.views import (
            VerificationPreferenceViewSet,
            VerificationViewSet,
        )

        for view_cls in (
            AuditLogViewSet, SecurityStatusViewSet, SessionViewSet,
            VerificationViewSet, VerificationPreferenceViewSet, OAuthLinkViewSet,
        ):
            assert _admits(rf, view_cls, guest) is True, view_cls.__name__

    def test_the_authenticator_change_door_is_shut_to_a_guest(self, rf, guest):
        """A change flow proves the CURRENT authenticator first, and a guest
        holds none — setting an address on an anonymous session promotes it,
        which is the other door and the only sanctioned one."""
        from django.contrib.auth import get_user_model

        from stapel_auth.otp.views import AuthenticatorChangeViewSet

        assert _admits(rf, AuthenticatorChangeViewSet, guest) is False
        account = get_user_model().objects.create_user(
            username="declared-account", email="declared@example.com",
        )
        assert _admits(rf, AuthenticatorChangeViewSet, account) is True
