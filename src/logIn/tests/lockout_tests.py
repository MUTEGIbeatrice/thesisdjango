from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse

class LockoutTests(TestCase):
    def setUp(self):
        self.client = Client()
        # Create admin user with staff and superuser status
        self.admin = User.objects.create_user(
            username='admin',
            password='testpass123',
            is_staff=True,
            is_superuser=True
        )
        # Create regular user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.login_url = reverse('login')
        self.lockout_url = reverse('lockout')
        self.stats_url = reverse('lockout_stats')  # Using correct name from urls.py

    def test_lockout_statistics_admin_access(self):
        self.client.force_login(self.admin)
        response = self.client.get(self.stats_url)
        self.assertEqual(response.status_code, 200)

    def test_lockout_statistics_regular_user_access(self):
        self.client.force_login(self.user)
        response = self.client.get(self.stats_url)
        self.assertEqual(response.status_code, 403)

    def test_progressive_lockout(self):
        # Test 3 failed login attempts
        for i in range(3):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'wrongpass',
                'g-recaptcha-response': 'dummy'  # Bypass CAPTCHA
            })
            if i < 2:
                self.assertContains(response, "Invalid Credentials")
            else:
                self.assertRedirects(response, self.lockout_url)
