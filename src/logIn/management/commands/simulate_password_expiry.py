# To simulate password expiry by setting a test user's date_joined to 91 days ago
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from datetime import timedelta

class Command(BaseCommand):
    help = 'Simulate password expiry by setting a test user\'s date_joined to 91 days ago'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username for the test user', default='testuser')

    def handle(self, *args, **options):
        username = options['username']
        User = get_user_model()

        try:
            user = User.objects.get(username=username)
            self.stdout.write(f"User '{username}' found.")
        except User.DoesNotExist:
            # Create the user if it does not exist
            user = User.objects.create_user(username=username, password='testpass123')
            self.stdout.write(f"User '{username}' created.")

        # Set date_joined to 91 days ago to simulate password expiry
        user.date_joined = now() - timedelta(days=91)
        user.save()
        self.stdout.write(f"User '{username}' date_joined set to {user.date_joined} to simulate password expiry.")
