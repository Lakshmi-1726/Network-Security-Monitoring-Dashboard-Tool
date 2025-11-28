import random
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from network_monitor.models import NetworkEvent, Alert
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = "Simulate random network events over the past 2 weeks with uneven daily distribution"

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=100, help='Total number of events to generate')

    def handle(self, *args, **options):
        EVENT_TYPES = ['connection', 'login_failure', 'active_user', 'port_scan', 'malware', 'other']
        SEVERITIES = ['low', 'medium', 'high', 'critical']
        total_events = options['count']
        days_range = 14  # Past 2 weeks

        users = list(User.objects.all())
        if not users:
            self.stdout.write(self.style.WARNING("⚠️ No users found. Create at least one user first."))
            return

        now = timezone.now()

        # Step 1: Random "activity weights" for each day (some days busy, some quiet)
        day_weights = [random.randint(0, 10) for _ in range(days_range)]
        total_weight = sum(day_weights) or 1
        events_per_day = [max(0, int(total_events * (w / total_weight))) for w in day_weights]

        # Ensure we generate the exact total count (adjust due to rounding)
        difference = total_events - sum(events_per_day)
        if difference > 0:
            for i in random.sample(range(days_range), difference):
                events_per_day[i] += 1

        created_events = 0
        day_event_summary = {}

        # Step 2: Generate events
        for days_ago, num_events in enumerate(events_per_day):
            event_date = now - timedelta(days=days_ago)
            day_event_summary[event_date.date()] = num_events

            for _ in range(num_events):
                if created_events >= total_events:
                    break

                event_type = random.choice(EVENT_TYPES)
                severity = random.choice(SEVERITIES)
                user = random.choice(users) if event_type == 'active_user' else None
                source_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
                message = f"Simulated {event_type} event with {severity} severity"

                # Random time within that day
                random_seconds = random.randint(0, 86399)
                random_timestamp = event_date.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(seconds=random_seconds)

                # Make sure datetime is timezone-aware
                if timezone.is_naive(random_timestamp):
                    random_timestamp = timezone.make_aware(random_timestamp)

                # Create event and update timestamp
                event = NetworkEvent.objects.create(
                    event_type=event_type,
                    severity=severity,
                    source_ip=source_ip,
                    message=message,
                    user=user
                )
                event.timestamp = random_timestamp
                event.save(update_fields=['timestamp'])

                # Create alert for high or critical events
                if severity in ['high', 'critical']:
                    Alert.objects.create(event=event)

                created_events += 1

        # Step 3: Log summary
        self.stdout.write(self.style.SUCCESS(
            f"\n✅ Successfully generated {created_events} events across the past 2 weeks (uneven distribution).\n"
        ))

        self.stdout.write("📅 Daily event distribution:")
        for day, count in sorted(day_event_summary.items()):
            self.stdout.write(f"  {day}: {count} events")
