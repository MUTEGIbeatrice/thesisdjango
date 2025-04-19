from django.test import TestCase, Client
from django.urls import reverse
from django.core.cache import cache
from unittest.mock import patch

def fake_ratelimit_decorator(*args, **kwargs):
    def decorator(func):
        def wrapper(request, *args, **kwargs):
            # Simulate the 'limited' attribute on the 6th call
            if not hasattr(wrapper, 'call_count'):
                wrapper.call_count = 0
            wrapper.call_count += 1
            if wrapper.call_count > 5:
                setattr(request, 'limited', True)
            else:
                setattr(request, 'limited', False)
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

class LoginRateLimitTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.login_url = reverse('login')  # Adjust if your login URL name is different
        self.username = 'testuser'
        self.password = 'testpassword'

    @patch('logIn.views.verify_recaptcha', return_value=True)
    @patch('logIn.views.ratelimit', side_effect=fake_ratelimit_decorator)
    def test_login_rate_limit(self, mock_ratelimit, mock_verify_recaptcha):
        # Clear cache before test
        cache.clear()

        post_data = {
            'username': self.username,
            'password': self.password,
            'g-recaptcha-response': 'dummy-response',  # This value is ignored due to mocking
        }

        # Send 5 POST requests within rate limit
        for _ in range(5):
            response = self.client.post(self.login_url, post_data)
            # We expect normal response (not blocked)
            self.assertNotContains(response, "Too many login attempts", status_code=200)

        # 6th request should be blocked by rate limit
        response = self.client.post(self.login_url, post_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Too many login attempts", response.content.decode())