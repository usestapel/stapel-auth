

class TestOAuthCallbackPathSetting:
    """The redirect_uri is registered in a THIRD PARTY's console. A library
    that moves it (as the /v1/ URL canon did) breaks every live OAuth app
    with `redirect_uri_mismatch` and no way to fix it from code — so the
    path is a setting, and a deployment can pin what its provider knows."""

    def _uri(self, settings, **over):
        from rest_framework.test import APIRequestFactory

        from stapel_auth.otp.views import AuthViewSet

        for k, v in over.items():
            setattr(settings, k, v)
        request = APIRequestFactory().get("/")
        return AuthViewSet()._build_callback_uri(request, "google")

    def test_defaults_to_the_current_v1_route(self, settings):
        uri = self._uri(
            settings,
            OAUTH_CALLBACK_BASE_URL="https://app.example.com",
            URL_PREFIX="auth/",
        )
        assert uri == "https://app.example.com/auth/api/v1/oauth/google/callback"

    def test_a_deployment_can_pin_the_registered_path(self, settings):
        settings.STAPEL_AUTH = {
            **getattr(settings, "STAPEL_AUTH", {}),
            "OAUTH_CALLBACK_PATH": "/{url_prefix}api/oauth/{provider}/callback",
        }
        uri = self._uri(
            settings,
            OAUTH_CALLBACK_BASE_URL="https://app.example.com",
            URL_PREFIX="auth/",
        )
        assert uri == "https://app.example.com/auth/api/oauth/google/callback"
