import time
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.test import RequestFactory
from django.core.cache import cache
from logIn.utils import LOCKOUT_STAGES
from axes.signals import user_locked_out  # Import the signal

class Command(BaseCommand):
    help = 'Test the progressive lockout mechanism by simulating failed logins'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username to target', default='testuser')
        parser.add_argument('--attempts', type=int, help='Number of login attempts', default=20)
        parser.add_argument('--delay', type=float, help='Delay between attempts in seconds', default=0.5)

    def handle(self, *args, **options):
        username = options['username']
        attempts = options['attempts']
        delay = options['delay']

        self.stdout.write(f"Testing progressive lockout for user '{username}' with {attempts} attempts.")

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(f"User '{username}' does not exist.")
            return

        factory = RequestFactory()

        for i in range(attempts):
            request = factory.post('/login/', data={'username': username, 'password': 'wrongpassword'})
            user = authenticate(request=request, username=username, password='wrongpassword')
            if user is None:
                self.stdout.write(f"Attempt {i+1}: Failed login for user '{username}'")
                failed_attempts = cache.get(f'failed_attempts_{username}', 0) + 1
                cache.set(f'failed_attempts_{username}', failed_attempts)

                # Check lockout status based on failed attempts
                user_locked_out.send(sender=self.__class__, request=request, user=None, ip_address=request.META.get('REMOTE_ADDR'))
                for attempts_threshold, lockout_minutes in LOCKOUT_STAGES:
                    if failed_attempts >= attempts_threshold:
                        expected_lockout = lockout_minutes
                        self.stdout.write(f"User '{username}' should be locked out for {expected_lockout} minutes after {failed_attempts} failed attempts.")
                        break
            else:
                self.stdout.write(f"Attempt {i+1}: Unexpected success for user '{username}'")
            time.sleep(delay)

        self.stdout.write("Progressive lockout test completed.")