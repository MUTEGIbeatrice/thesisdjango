from django.test import TestCase
from django.contrib.auth.models import User
from django.utils.timezone import now
from datetime import timedelta
from time import sleep
from logIn.models import UserProfile

class OTPExpirationTestCase(TestCase):
    def test_otp_expiry(self):
        # Create test user
        user = User.objects.create_user(username='otpuser', email='otp@example.com', password='otppass')
        user.save()

        # Create or get UserProfile
        profile, created = UserProfile.objects.get_or_create(user=user)

        # Generate OTP and set expiry to 10 minutes from now
        profile.otp = '123456'
        profile.otp_expiry = now() + timedelta(minutes=10)
        profile.save()

        # Check OTP validity immediately (should be valid)
        is_valid_now = profile.is_otp_valid()
        print(f"OTP valid immediately after generation? {is_valid_now}")
        self.assertTrue(is_valid_now)

        # Calculate time until expiration
        time_until_expiry = profile.otp_expiry - now()
        print(f"Time until OTP expiration: {time_until_expiry}")

        # Simulate waiting for 10 minutes and 1 second (real time)
        print("Waiting for OTP to expire...")
        sleep(601)  # Sleep for 601 seconds (10 minutes and 1 second)

        # Refresh profile from database
        profile.refresh_from_db()

        # Check OTP validity after waiting (should be invalid)
        is_valid_after_wait = profile.is_otp_valid()
        print(f"OTP valid after waiting 10 minutes? {is_valid_after_wait}")
        self.assertFalse(is_valid_after_wait)

        # Calculate time since expiration
        time_since_expiry = now() - profile.otp_expiry
        print(f"Time since OTP expired: {time_since_expiry}")
