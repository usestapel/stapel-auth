"""Serializer seams.

Views expose their serializers as overridable ``*_request_serializer_class`` /
``*_response_serializer_class`` attributes with matching
``get_*_serializer_class()`` getters (see stapel_auth.utils.SerializerSeamsMixin),
so a host can subclass a view and swap a serializer. This proves the swap is
picked up by the handler end to end.
"""

from rest_framework import serializers
from rest_framework.test import APIRequestFactory, APITestCase

from stapel_auth.magic_link.serializers import MagicLinkRequestResponseSerializer
from stapel_auth.magic_link.views import MagicLinkViewSet


class _ExtendedResponseSerializer(MagicLinkRequestResponseSerializer):
    """Response serializer with an extra field, as a host would add one."""

    flavour = serializers.SerializerMethodField()

    def get_flavour(self, obj):
        return "overridden"


class _CustomMagicLinkViewSet(MagicLinkViewSet):
    response_serializer_class = _ExtendedResponseSerializer


class SerializerSeamTests(APITestCase):
    def test_swapping_serializer_class_attribute_changes_serializer_used(self):
        # The getter resolves the overridden attribute on the subclass ...
        self.assertIs(
            _CustomMagicLinkViewSet().get_response_serializer_class(),
            _ExtendedResponseSerializer,
        )
        # ... while the base view keeps its default.
        self.assertIs(
            MagicLinkViewSet().get_response_serializer_class(),
            MagicLinkRequestResponseSerializer,
        )

        # And the handler actually serializes with the override: the extra
        # field shows up in the response payload.
        factory = APIRequestFactory()
        request = factory.post(
            "/auth/api/magic/request/",
            {"email": "seam-nobody@example.com"},
            format="json",
        )
        response = _CustomMagicLinkViewSet.as_view({"post": "request_link"})(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.get("flavour"), "overridden")
        self.assertIn("message", response.data)
