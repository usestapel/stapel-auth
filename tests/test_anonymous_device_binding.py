"""``device_id`` dedups a guest session — it must never *be* the session.

``POST /anonymous/`` hands back JWTs for the guest parked under a ``device_id``.
That string is caller-supplied and proves nothing: on its own it made the 60s
dedup slot a bearer under a name anyone could send. With a storefront minting
guests silently and ``user.merged`` reassigning a guest's favourites and chat
threads onto whatever account it signs into, riding someone's slot stopped
being "an unattached session" and became theft of their rows.

Two things close it, and the tests come in that pair:

* the slot is keyed by the caller's address as well as the ``device_id``, so a
  stolen string claims nothing from another client;
* a ``device_id`` short enough to guess is refused outright.

The dedup itself must keep working — same client, same id, same guest — or the
fix is a silent removal of the feature the cookie-less clients depend on.
"""
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from stapel_auth.errors import ERR_400_DEVICE_ID_WEAK

User = get_user_model()

#: A well-formed device id: 32 random hex chars, the shape a client library
#: actually generates (``uuid4().hex``).
GOOD_DEVICE_ID = "9f2c41a7be5d4e08b1c73a6d5e0f8241"


@override_settings(URL_PREFIX="", STAPEL_AUTH={"ANONYMOUS_RATE_LIMIT_PER_HOUR": 0})
class DeviceSlotIsBoundToTheCallerTests(APITestCase):
    """A slot parked by one client cannot be claimed by another."""

    def setUp(self):
        cache.clear()

    def _mint(self, device_id=None, ip="10.0.0.7"):
        # A FRESH client each time, cookie jar and all: keeping cookies would
        # hand back the anonymous JWT and the view would reuse THAT session,
        # which is a different path than the one under test.
        body = {"device_id": device_id} if device_id is not None else {}
        return self.client_class().post(
            reverse("anonymous"), body, format="json", REMOTE_ADDR=ip
        )

    def _guest_id(self, response):
        self.assertEqual(
            response.status_code, status.HTTP_201_CREATED, response.content
        )
        self.assertTrue(response.data["user"]["is_anonymous"])
        return response.data["user"]["id"]

    def test_another_client_cannot_claim_the_slot(self):
        """The theft, closed: same device_id, different address, new guest.

        Before the address binding this returned the FIRST caller's guest —
        tokens included — to anybody who guessed or sniffed the string.
        """
        victim = self._guest_id(self._mint(GOOD_DEVICE_ID, ip="10.0.0.7"))
        thief = self._guest_id(self._mint(GOOD_DEVICE_ID, ip="10.0.0.8"))
        self.assertNotEqual(
            thief,
            victim,
            "a second client was handed the first client's guest session",
        )
        self.assertEqual(User.objects.filter(is_anonymous=True).count(), 2)

    def test_the_same_client_still_reuses_its_guest(self):
        """The dedup is bound, not removed — the legitimate flow is untouched."""
        first = self._guest_id(self._mint(GOOD_DEVICE_ID, ip="10.0.0.7"))
        for _ in range(3):
            again = self._guest_id(self._mint(GOOD_DEVICE_ID, ip="10.0.0.7"))
            self.assertEqual(again, first, "device dedup stopped working")
        self.assertEqual(User.objects.filter(is_anonymous=True).count(), 1)

    def test_the_binding_follows_the_declared_client_ip_header(self):
        """Behind a proxy the slot follows the DECLARED header, not REMOTE_ADDR.

        Same helper as the mint budget (``stapel_core.netintel.client_ip``), so
        there is exactly one answer to "who is the caller" on this endpoint.
        """
        def mint(ip):
            return self.client_class().post(
                reverse("anonymous"),
                {"device_id": GOOD_DEVICE_ID},
                format="json",
                HTTP_X_REAL_IP=ip,
                REMOTE_ADDR="10.0.0.7",
            )

        with override_settings(
            STAPEL_NETINTEL={"TRUSTED_PROXY_HEADER": "HTTP_X_REAL_IP"}
        ):
            mine = self._guest_id(mint("1.2.3.4"))
            self.assertEqual(self._guest_id(mint("1.2.3.4")), mine)
            self.assertNotEqual(self._guest_id(mint("1.2.3.5")), mine)


@override_settings(URL_PREFIX="", STAPEL_AUTH={"ANONYMOUS_RATE_LIMIT_PER_HOUR": 0})
class DeviceIdMustNotBeGuessableTests(APITestCase):
    """A dedup key that doubles as a bearer needs the entropy of one."""

    def setUp(self):
        cache.clear()

    def _post(self, body):
        return self.client_class().post(
            reverse("anonymous"), body, format="json", REMOTE_ADDR="10.0.0.7"
        )

    def test_a_guessable_device_id_is_refused(self):
        for value in ["device1", "test", "1", "abc-123"]:
            with self.subTest(device_id=value):
                response = self._post({"device_id": value})
                self.assertEqual(
                    response.status_code, status.HTTP_400_BAD_REQUEST, response.content
                )
                self.assertEqual(
                    response.data["localizable_error"], ERR_400_DEVICE_ID_WEAK
                )
                self.assertEqual(response.data["params"]["field"], "device_id")
        self.assertEqual(User.objects.filter(is_anonymous=True).count(), 0)

    def test_the_refusal_says_what_shape_is_expected(self):
        """A client author has to be able to fix it from the text alone."""
        from stapel_auth.errors import AUTH_ERRORS

        text = AUTH_ERRORS[ERR_400_DEVICE_ID_WEAK]
        self.assertIn("16", text)
        self.assertIn("random", text.lower())

    def test_the_shapes_a_client_library_generates_are_accepted(self):
        for value in [str(uuid.uuid4()), uuid.uuid4().hex, "Zm9vYmFyYmF6cXV4MTIzNA"]:
            with self.subTest(device_id=value):
                response = self._post({"device_id": value})
                self.assertEqual(
                    response.status_code, status.HTTP_201_CREATED, response.content
                )

    def test_no_device_id_still_mints(self):
        """The dedup is optional — a caller that sends nothing gets a guest."""
        response = self._post({})
        self.assertEqual(
            response.status_code, status.HTTP_201_CREATED, response.content
        )
        self.assertTrue(response.data["user"]["is_anonymous"])
        self.assertTrue(response.data["tokens"]["access"])
