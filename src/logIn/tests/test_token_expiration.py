from django.test import TestCase
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from datetime import timedelta
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

        # Simulate waiting for expiration (e.g., simulate 25 hours later)
        user.date_joined -= timedelta(hours=25)  # Simulate as if the user joined earlier
        user.save()
        
        is_valid_after_25hrs = email_token_generator.check_token(user, token)
        print(f"Token valid after 25 hours? {is_valid_after_25hrs}")
        
        is_valid_after_49hrs = email_token_generator.check_token(user, token)
        print(f"Token valid after 49 hours? {is_valid_after_49hrs}")

        # Simulate waiting for expiration (e.g., simulate 73 hours later)
        user.date_joined -= timedelta(hours=73)  # Simulate as if the user joined earlier
        user.save()
        
        is_valid_after_73hrs = email_token_generator.check_token(user, token)
        print(f"Token valid after 73 hours? {is_valid_after_73hrs}")

      # Simulate waiting for expiration (e.g., simulate 97 hours later)
        user.date_joined -= timedelta(hours=97)  # Simulate as if the user joined earlier
        user.save()
        
        is_valid_after_97hrs = email_token_generator.check_token(user, token)
        print(f"Token valid after 97 hours? {is_valid_after_97hrs}")