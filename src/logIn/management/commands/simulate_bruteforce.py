import time
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.test import RequestFactory
from logIn.models import LockoutLog
from axes.handlers.proxy import AxesProxyHandler
import logging

class Command(BaseCommand):
    help = 'Simulate brute force attack with detailed lockout status and features'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username to target', default='testuser')
        parser.add_argument('--attempts', type=int, help='Number of login attempts', default=10)
        parser.add_argument('--delay', type=float, help='Delay between attempts in seconds', default=0.5)
        parser.add_argument('--ip', type=str, help='IP address to simulate from', default='127.0.0.1')
        parser.add_argument('--simulate-success-after-lockout', action='store_true', help='Simulate a successful login after lockout expires')

    def handle(self, *args, **options):
        username = options['username']
        attempts = options['attempts']
        delay = options['delay']
        ip = options['ip']
        simulate_success_after_lockout = options['simulate_success_after_lockout']

        self.stdout.write(f"Starting brute force simulation for user '{username}' from IP {ip} with {attempts} attempts.")

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(f"User '{username}' does not exist.")
            return

        factory = RequestFactory()
        logger = logging.getLogger(__name__)
        proxy_handler = AxesProxyHandler()

        for i in range(attempts):
            request = factory.post('/login/', data={'username': username, 'password': 'wrongpassword'})
            # Manually set REMOTE_ADDR to simulate IP
            request.META['REMOTE_ADDR'] = ip
            try:
                user = authenticate(request=request, username=username, password='wrongpassword')
                LockoutLog.objects.create(
                    username=username,
                    ip_address='127.0.0.1',
                    is_simulation=True
                )

                # Check if IP is locked out
                ip = '127.0.0.1'
                is_locked = proxy_handler.is_locked(request, credentials={'username': username, 'ip': ip})
                if is_locked:
                    self.stdout.write(f"IP {ip} is currently LOCKED OUT after attempt {i+1}.")
                else:
                    self.stdout.write(f"IP {ip} is NOT locked out after attempt {i+1}.")

            except Exception as e:
                logger.error(f"Authentication error on attempt {i+1}: {e}")
                self.stdout.write(f"Attempt {i+1}: Authentication error")
            time.sleep(delay)

        self.stdout.write("Brute force simulation completed.")