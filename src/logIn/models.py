from django.db import models
from django.contrib.auth.models import User #IMPORTING USER MODEL

# Create your models here.

#USER PROFILE IS AN EXTENSION TO dJANGO'S MODEL OF USERS' PROFILE

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_secret = models.CharField(max_length=32, blank=True, null=True)  # Store OTP secret
    otp = models.CharField(max_length=6, blank=True, null=True)  # Temporary storage for OTP
    otp_expiry = models.DateTimeField(null=True, blank=True)

    gender = models.CharField(
        max_length=6,
        choices=[('MALE', 'MALE'),('FEMALE', 'FEMALE')],
        blank=True, null=True
    )
    department_name = models.CharField(
        max_length=100,
        choices=[('Name 1', 'Name 1'),('Name 2', 'Name 2'),('Name 3', 'Name 3'),('Name 4', 'Name 4')],
        blank=True, null=True
    )
    department_allocation =  models.CharField(
        max_length=100,
        choices=[('Location 1', 'Location 1'),('Location 2', 'Location 2'),('Location 3', 'Location 3'),('Location 4', 'Location 4')],
        blank=True, null=True
    )
    
    def __str__(self):
        return f"{self.user.username}'s Profile"