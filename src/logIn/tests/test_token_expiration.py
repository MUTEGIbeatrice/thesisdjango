import unittest
import os
import django
from django.contrib.auth import get_user_model
from logIn.tokens import EmailVerificationTokenGenerator
from django.utils import timezone
from unittest.mock import patch

# Setup Django environment for standalone test
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'loginSystem.settings')
django.setup()

class EmailVerificationTokenGeneratorTest(unittest.TestCase):
    def setUp(self):
        User = get_user_model()
        # Use a unique username to avoid IntegrityError
        import uuid
        unique_username = f'testuser_{uuid.uuid4().hex[:8]}'
        self.user = User.objects.create_user(username=unique_username, password='testpass')
        self.token_generator = EmailVerificationTokenGenerator()

    def test_token_valid_immediately(self):
        token = self.token_generator.make_token(self.user)
        self.assertTrue(self.token_generator.check_token(self.user, token))

    @patch('django.utils.timezone.now')
    def test_token_expired_after_24_hours(self, mock_now):
        token = self.token_generator.make_token(self.user)
        # Simulate time after 49 hours (2 intervals of 24 hours + 1 hour)
        mock_now.return_value = timezone.now() + timezone.timedelta(hours=49)
        self.assertFalse(self.token_generator.check_token(self.user, token))

if __name__ == '__main__':
    unittest.main()
