"""
GDPR bus consumer for iron-auth.

Handles gdpr.export.requested and gdpr.delete.requested events,
uploads auth data to object storage, and publishes completion events.

Run one instance per auth service deployment:

    python manage.py consume_gdpr
"""
from django.core.management.base import BaseCommand

from stapel_core.bus.event import Event
from stapel_core.bus.router import get_bus
from stapel_core.gdpr import (
    GDPR_DELETE_REQUESTED,
    GDPR_EXPORT_REQUESTED,
    GDPRServiceConsumerCommand,
)


class Command(GDPRServiceConsumerCommand, BaseCommand):
    help = 'Consume GDPR export/delete requests from the bus'

    # Must match the entry in GDPR_COLLECTING_SERVICES on the GDPR service.
    # The CI linter (scripts/check_gdpr_services.py) verifies this.
    gdpr_service_name = 'auth'

    def get_gdpr_provider(self):
        from stapel_auth.gdpr import AuthGDPRProvider
        return AuthGDPRProvider()

    def add_arguments(self, parser):
        parser.add_argument('--poll-timeout', type=float, default=0.1)

    def handle(self, *args, **options):
        bus = get_bus()
        self.stdout.write(
            f'Starting GDPR consumer: service={self.gdpr_service_name} '
            f'group={self.consumer_group} topics={self.topics}'
        )
        bus.consume(
            self.topics,
            self.consumer_group,
            self._dispatch,
            poll_timeout=options['poll_timeout'],
        )

    def _dispatch(self, event: Event) -> None:
        self.handle_gdpr_event(event)
