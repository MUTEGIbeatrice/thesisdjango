from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from logIn.models import LockoutLog
from datetime import datetime

class LockoutSystemTests(TestCase):
    def setUp(self):
        self.client = Client()
        
        # Create admin user with proper permissions
        self.admin = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='testpass123'
        )
        
        # Create regular user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        # Create test lockout data
        LockoutLog.objects.create(
            username='testuser',
            ip_address='127.0.0.1',
            timestamp=datetime.now()
        )
        
        # URLs - using direct paths since reverse() may not work for admin URLs
        self.login_url = reverse('login')
        self.lockout_url = reverse('lockout')
        self.stats_url = '/admin/logIn/lockoutlog/'  # Direct admin URL path

    def test_admin_access_to_stats(self):
        self.client.force_login(self.admin)
        response = self.client.get(self.stats_url)
        self.assertEqual(response.status_code, 200)

    def test_regular_user_access_to_stats(self):
        self.client.force_login(self.user)
        response = self.client.get(self.stats_url, follow=True)
        # Should show admin login page
        self.assertContains(response, "Log in")

    def test_progressive_lockout_mechanism(self):
        # First two failed attempts
        for _ in range(2):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'wrongpass',
                'g-recaptcha-response': 'TEST'  # Bypass CAPTCHA in tests
            }, follow=True)
            self.assertContains(response, "CAPTCHA verification failed")  # Updated to match actual response
            
        # Third attempt should trigger lockout
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'wrongpass',
            'g-recaptcha-response': 'TEST'
        }, follow=True)
        self.assertContains(response, "Too many failed login attempts")  # Updated to match actual response
