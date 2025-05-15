from django.test import TestCase
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from datetime import timedelta
from unittest.mock import patch
import time
from logIn.tokens import email_token_generator

class TokenExpirationTestCase(TestCase):
    def test_token_expiry(self):
        # Create user with is_active=True initially
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpass')
        user.is_active = False
        user.save()

        # Generate token while user is active
        token = email_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Deactivate user after token generation
        user.is_active = False
        user.save()
        
        # Check validity immediately
        is_valid_now = email_token_generator.check_token(user, token)
        print(f"Token valid immediately after generation? {is_valid_now}")

        # Patch _num_seconds method to simulate token age in seconds
        original_num_seconds = email_token_generator._num_seconds

        def fake_num_seconds_23(dt):
            # Simulate 23 hours later
            return original_num_seconds(dt) + 23 * 3600

        with patch.object(email_token_generator, '_num_seconds', side_effect=fake_num_seconds_23):
            is_valid_after_23hrs = email_token_generator.check_token(user, token)
            print(f"Token valid after 23 hours? {is_valid_after_23hrs}")

        def fake_num_seconds_25(dt):
            return original_num_seconds(dt) + 25 * 3600

        with patch.object(email_token_generator, '_num_seconds', side_effect=fake_num_seconds_25):
            is_valid_after_25hrs = email_token_generator.check_token(user, token)
            print(f"Token valid after 25 hours? {is_valid_after_25hrs}")

        def fake_num_seconds_49(dt):
            return original_num_seconds(dt) + 49 * 3600

        with patch.object(email_token_generator, '_num_seconds', side_effect=fake_num_seconds_49):
            is_valid_after_49hrs = email_token_generator.check_token(user, token)
            print(f"Token valid after 49 hours? {is_valid_after_49hrs}")
