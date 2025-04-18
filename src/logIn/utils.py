from django.shortcuts import render
import pyotp, random
from django.core.mail import send_mail
from django.conf import settings
from .models import UserProfile
from django.utils import timezone
from datetime import timedelta 
from django.core.cache import cache
from django.utils import timezone



# Progressive lockout settings
LOCKOUT_STAGES = [
    (3, 5),    # 3 attempts -> 5 min lockout
    (6, 10),   # 6 attempts -> 10 min lockout
    (9, 15),   # 9 attempts -> 15 min lockout
    (12, 30),  # 12 attempts -> 30 min lockout
    (15, 60)   # 15+ attempts -> 60 min lockout
]

def get_lockout_timeout(failed_attempts):
    """Calculate lockout timeout based on failed attempts"""
    for attempts, minutes in LOCKOUT_STAGES:
        if failed_attempts <= attempts:
            return timedelta(minutes=minutes)
    return timedelta(minutes=60)  # Default max timeout

def log_lockout_event(username, ip_address, failed_attempts, timeout):
    """Log lockout events for admin monitoring"""
    from .models import LockoutLog
    LockoutLog.objects.create(
        username=username,
        ip_address=ip_address,
        timestamp=timezone.now(),
        is_simulation=False
    )

# Lockout
def custom_lockout_callable(request, credentials):
    """
    Progressive lockout function with escalating timeouts
    """
    username = credentials.get('username', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    cache_key = f'failed_attempts_{username}'
    
    # Get current failed attempts
    failed_attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, failed_attempts)
    
    # Calculate timeout
    timeout = get_lockout_timeout(failed_attempts)
    
    # Log the lockout event
    log_lockout_event(username, ip_address, failed_attempts, timeout)
    
    # Set lockout in cache
    lockout_key = f'lockout_{username}'
    cache.set(lockout_key, True, timeout=timeout.seconds)
    
    context = {
        'timeout_minutes': timeout.seconds // 60,
        'failed_attempts': failed_attempts
    }
    return render(request, 'logIn/lockout.html', context, status=403)




# Generate OTP secret for the user
def generate_otp_secret(user):
    # Generate a secure random OTP
    otp = str(random.randint(100000, 999999))  # 6-digit OTP
    
    # Get or create user profile
    user_profile, created = UserProfile.objects.get_or_create(user=user)
    
    # Set OTP and expiry (10 minutes from now)
    user_profile.otp = otp
    user_profile.otp_expiry = timezone.now() + timedelta(minutes=10)
    user_profile.save()
    
    return otp


# Send OTP to the user's email
def send_otp(email, otp):
    subject = '🔐 Secure Access: Your OTP Code'
    message = f"""
    Hello,

    Here is your One-Time Password (OTP) for logging in: **{otp}**

    Please do not share this code with anyone. It is valid for a limited time.

    If you did not request this code, please ignore this email.

    Regards,
    Security Team
    """
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
