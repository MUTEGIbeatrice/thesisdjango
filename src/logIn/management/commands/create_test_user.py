from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Create a test user for brute force simulation'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username for the test user', default='testuser')
        parser.add_argument('--password', type=str, help='Password for the test user', default='testpass123')

    def handle(self, *args, **options):
        username = options['username']
        password = options['password']

        User = get_user_model()
        if User.objects.filter(username=username).exists():
            self.stdout.write(f"User '{username}' already exists.")
        else:
            User.objects.create_user(username=username, password=password)
            self.stdout.write(f"User '{username}' created successfully.")
