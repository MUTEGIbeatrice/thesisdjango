from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from logIn.models import LockoutLog
from datetime import datetime

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    print('User:{}, logged in through page {}.'.format(user.username,request.META.get('HTTP_REFERER')))

@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    # Log failed login attempts into LockoutLog
    LockoutLog.objects.create(
        username=credentials.get('username'),
        ip_address=request.META.get('REMOTE_ADDR'),
        timestamp=datetime.now(),
        attempts=1  # Increment attempts for each failed login
    )
    print('User:{}, failed to log in through page {}.'.format(credentials.get('username'), request.META.get('HTTP_REFERER')))

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    print('User:{}, logged out through page {}.'.format(user.username,request.META.get('HTTP_REFERER')))