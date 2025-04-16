from django.test import TestCase, Client, RequestFactory
from django.contrib.auth.models import User
from django.core.cache import cache
from django.urls import reverse
import time

class LockoutSystemTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            is_staff=True
        )
        self.login_url = reverse('login')
        self.lockout_url = reverse('lockout')
        self.stats_url = reverse('lockout_stats')
        
        # Mock reCAPTCHA verification
        from logIn.views import verify_recaptcha
        self.original_verify_recaptcha = verify_recaptcha
        verify_recaptcha = lambda request, response: True

    def tearDown(self):
        from logIn.views import verify_recaptcha
        verify_recaptcha = self.original_verify_recaptcha

    def test_progressive_lockout(self):
        # Test initial failed attempts
        for i in range(1, 4):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'wrongpass',
                'g-recaptcha-response': 'dummy'
            }, follow=True)
            if i < 3:
                self.assertContains(response, "Invalid Credentials")
            else:
                self.assertRedirects(response, self.lockout_url)
                
    def test_admin_stats_access(self):
        # Create request object for Axes
        request = self.factory.get(self.stats_url)
        request.user = self.user
        
        # Test staff can access lockout stats
        self.client.force_login(self.user)
        response = self.client.get(self.stats_url)
        self.assertEqual(response.status_code, 200)
        
    def test_normal_user_stats_access(self):
        # Create normal user
        normal_user = User.objects.create_user(
            username='normaluser',
            password='testpass123',
            is_staff=False
        )
        
        # Create request object for Axes
        request = self.factory.get(self.stats_url)
        request.user = normal_user
        
        # Test non-staff cannot access stats
        self.client.force_login(normal_user)
        response = self.client.get(self.stats_url)
        self.assertEqual(response.status_code, 403)
