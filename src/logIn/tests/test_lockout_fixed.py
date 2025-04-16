from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core.cache import cache
from django.urls import reverse
import time

class LockoutSystemTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username='adminuser',
            password='testpass123',
            is_staff=True
        )
        self.normal_user = User.objects.create_user(
            username='normaluser',
            password='testpass123',
            is_staff=False
        )
        self.login_url = reverse('login')
        self.lockout_url = reverse('lockout')
        self.stats_url = reverse('lockout-stats')  # Using hyphen to match urls.py
        
    def test_progressive_lockout(self):
        # Test failed login attempts
        for i in range(1, 4):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'wrongpass',
                'g-recaptcha-response': 'dummy'
            }, follow=True)
            if i < 3:
                self.assertContains(response, "Invalid Credentials", status_code=200)
            else:
                self.assertRedirects(response, self.lockout_url)

    def test_admin_stats_access(self):
        # Login as admin
        self.client.login(username='adminuser', password='testpass123')
        response = self.client.get(self.stats_url)
        self.assertEqual(response.status_code, 200)
        
    def test_normal_user_stats_access(self):
        # Login as normal user
        self.client.login(username='normaluser', password='testpass123')
        response = self.client.get(self.stats_url)
        # Should redirect since normal users can't access admin pages
        self.assertEqual(response.status_code, 302)
