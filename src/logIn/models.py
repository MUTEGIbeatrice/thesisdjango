from django.db import models
from django.contrib.auth.models import User #IMPORTING USER MODEL
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
import logging



# Create your models here.

class LockoutLog(models.Model):
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username} locked out at {self.timestamp} from {self.ip_address}"



#USER PROFILE IS AN EXTENSION TO dJANGO'S MODEL OF USERS' PROFILE
class UserProfile(models.Model):
    """
    Extends the default User model with additional fields:
    - otp: One-time password for 2FA
    - otp_expiry: When the OTP expires  
    - last_password_change: Track password changes
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_secret = models.CharField(max_length=32, blank=True, null=True)  # Store OTP secret
    otp = models.CharField(max_length=6, blank=True, null=True)  # Temporary storage for OTP
    otp_expiry = models.DateTimeField(null=True, blank=True)

    def is_otp_valid(self):
        if not self.otp or not self.otp_expiry:
            return False
        now = timezone.now()
        logger = logging.getLogger(__name__)
        logger.info(f"Checking OTP validity - Current: {now}, Expiry: {self.otp_expiry}")
        return now < self.otp_expiry

    gender = models.CharField(
        max_length=6,
        choices=[('MALE', 'MALE'), ('FEMALE', 'FEMALE')],
        blank=True, null=True
    )
    department_name = models.CharField(
        max_length=100,
        choices=[('Name 1', 'Name 1'), ('Name 2', 'Name 2'), ('Name 3', 'Name 3'), ('Name 4', 'Name 4')],
        blank=True, null=True
    )
    department_allocation = models.CharField(
        max_length=100,
        choices=[('Location 1', 'Location 1'), ('Location 2', 'Location 2'), ('Location 3', 'Location 3'), ('Location 4', 'Location 4')],
        blank=True, null=True
    )

    def __str__(self):
        try:
            username = getattr(self.user, 'username', None)
            if username:
                return f"{username}'s Profile"
            return "User Profile (No Username)"
        except Exception as e:
            return f"User Profile (Error: {e})"
        return "User Profile"
       