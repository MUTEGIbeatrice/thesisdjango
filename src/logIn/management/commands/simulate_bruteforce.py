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
        # Define command line arguments for the management command
        parser.add_argument('--username', type=str, help='Username to target', default='testuser')
        parser.add_argument('--attempts', type=int, help='Number of login attempts', default=10)
        parser.add_argument('--delay', type=float, help='Delay between attempts in seconds', default=0.5)
        parser.add_argument('--ip', type=str, help='IP address to simulate from', default='127.0.0.1')
        parser.add_argument('--simulate-success-after-lockout', action='store_true', help='Simulate a successful login after lockout expires')

    def handle(self, *args, **options):
        # Extract options from command line arguments
        username = options['username']
        attempts = options['attempts']
        delay = options['delay']
        ip = options['ip']
        simulate_success_after_lockout = options['simulate_success_after_lockout']

        self.stdout.write(f"Starting brute force simulation for user '{username}' from IP {ip} with {attempts} attempts.")

        # Get the user model and fetch the target user
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(f"User '{username}' does not exist.")
            return

        # Setup request factory and logger
        factory = RequestFactory()
        logger = logging.getLogger(__name__)
        proxy_handler = AxesProxyHandler()

        # Initialize variables to track lockout status and timing
        lockout_triggered_at_attempt = None
        start_time = time.time()

        # Loop through the number of login attempts
        for i in range(attempts):
            # Create a POST request simulating a login attempt with wrong password
            request = factory.post('/login/', data={'username': username, 'password': 'wrongpassword'})
            # Set the IP address in the request metadata
            request.META['REMOTE_ADDR'] = ip
            try:
                # Attempt to authenticate with wrong credentials
                user = authenticate(request=request, username=username, password='wrongpassword')
                # Log this simulation attempt in LockoutLog
                LockoutLog.objects.create(
                    username=username,
                    ip_address=ip,
                    is_simulation=True
                )

                # Check if the IP is currently locked out using AxesProxyHandler
                is_locked = proxy_handler.is_locked(request, credentials={'username': username, 'ip': ip})
                if is_locked:
                    # Record the attempt number and elapsed time when lockout is first triggered
                    if lockout_triggered_at_attempt is None:
                        lockout_triggered_at_attempt = i + 1
                        elapsed_time = time.time() - start_time
                        self.stdout.write(f"Lockout triggered at attempt {lockout_triggered_at_attempt} after {elapsed_time:.2f} seconds.")
                    self.stdout.write(f"IP {ip} is currently LOCKED OUT after attempt {i+1}.")
                else:
                    self.stdout.write(f"IP {ip} is NOT locked out after attempt {i+1}.")

            except Exception as e:
                # Log any authentication errors encountered during simulation
                logger.error(f"Authentication error on attempt {i+1}: {e}")
                self.stdout.write(f"Attempt {i+1}: Authentication error")
            # Wait for the specified delay before next attempt
            time.sleep(delay)

        # After all attempts, report if and when lockout was triggered
        total_elapsed_time = time.time() - start_time
        if lockout_triggered_at_attempt is None:
            self.stdout.write("Lockout was not triggered during the simulation.")
        else:
            self.stdout.write(f"Lockout was triggered at attempt {lockout_triggered_at_attempt} after {total_elapsed_time:.2f} seconds.")

        self.stdout.write("Brute force simulation completed.")