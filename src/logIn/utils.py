from django.shortcuts import render
import pyotp, random
from django.core.mail import send_mail
from django.conf import settings
from .models import UserProfile


# Lockout
def custom_lockout_callable(request, credentials):
    """
    Custom lockout function for Django Axes.
    Redirects the user to a lockout page when their account is locked.
    """
    return render(request, 'logIn/lockout.html', status=403)

# Generate OTP secret for the user
def generate_otp_secret(user):
    otp = pyotp.TOTP(pyotp.random_base32()).now()  # Secure OTP generation
    # Store OTP temporarily in user profile (or session)
    user_profile, created = UserProfile.objects.get_or_create(user=user)  # Ensure profile exists
    user_profile.otp = otp
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
