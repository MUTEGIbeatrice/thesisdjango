import time
import threading
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.test import RequestFactory
from logIn.models import LockoutLog
from axes.handlers.proxy import AxesProxyHandler
import logging

class Command(BaseCommand):
    help = 'Simulate distributed brute force attack from multiple IP addresses concurrently'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username to target', default='testuser')
        parser.add_argument('--attempts', type=int, help='Number of login attempts per IP', default=10)
        parser.add_argument('--delay', type=float, help='Delay between attempts in seconds', default=0.5)
        parser.add_argument('--ip-list', nargs='+', type=str, required=True, help='List of IP addresses to simulate from')
        parser.add_argument('--simulate-success-after-lockout', action='store_true', help='Simulate a successful login after lockout expires')

    def handle(self, *args, **options):
        username = options['username']
        attempts = options['attempts']
        delay = options['delay']
        ip_list = options['ip_list']
        simulate_success_after_lockout = options['simulate_success_after_lockout']

        self.stdout.write(f"Starting distributed brute force simulation for user '{username}' from IPs: {ip_list} with {attempts} attempts each.")

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(f"User '{username}' does not exist.")
            return

        factory = RequestFactory()
        logger = logging.getLogger(__name__)
        proxy_handler = AxesProxyHandler()

        lockout_triggered = threading.Event()
        lockout_info = {'attempt': None, 'ip': None}

        def attempt_login(ip_addr):
            for i in range(attempts):
                request = factory.post('/login/', data={'username': username, 'password': 'wrongpassword'})
                request.META['REMOTE_ADDR'] = ip_addr
                try:
                    authenticate(request=request, username=username, password='wrongpassword')
                    LockoutLog.objects.create(
                        username=username,
                        ip_address=ip_addr,
                        is_simulation=True
                    )
                    is_locked = proxy_handler.is_locked(request, credentials={'username': username, 'ip': ip_addr})
                    if is_locked:
                        if not lockout_triggered.is_set():
                            lockout_triggered.set()
                            lockout_info['attempt'] = i + 1
                            lockout_info['ip'] = ip_addr
                            self.stdout.write(f"Lockout triggered by IP {ip_addr} at attempt {i+1}.")
                        self.stdout.write(f"IP {ip_addr} is currently LOCKED OUT after attempt {i+1}.")
                    else:
                        self.stdout.write(f"IP {ip_addr} is NOT locked out after attempt {i+1}.")
                except Exception as e:
                    logger.error(f"Authentication error on attempt {i+1} from IP {ip_addr}: {e}")
                    self.stdout.write(f"Attempt {i+1} from IP {ip_addr}: Authentication error")
                time.sleep(delay)

        threads = []
        start_time = time.time()

        for ip_addr in ip_list:
            t = threading.Thread(target=attempt_login, args=(ip_addr,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        total_elapsed_time = time.time() - start_time
        if lockout_triggered.is_set():
            self.stdout.write(f"Lockout was triggered at attempt {lockout_info['attempt']} by IP {lockout_info['ip']} after {total_elapsed_time:.2f} seconds.")
        else:
            self.stdout.write("Lockout was not triggered during the distributed simulation.")

        self.stdout.write("Distributed brute force simulation completed.")
