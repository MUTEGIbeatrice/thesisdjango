#Signal handlers for user-related events. Includes actions to take when a user is created or locked out.
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import UserProfile
import logging
from django.core.mail import send_mail
from axes.signals import user_locked_out


# Initialize logger
logger = logging.getLogger(__name__)




#Signal receiver to automatically create UserProfile when a new User is created.    
@receiver(post_save, sender=get_user_model())
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        try:
            UserProfile.objects.get_or_create(user=instance)
            logger.info(f"Created UserProfile for {instance.username}")
        except Exception as e:
            logger.error(f"Error creating UserProfile: {e}")
            raise


#Signal receiver to save UserProfile when User is saved.
@receiver(post_save, sender=get_user_model())
def save_user_profile(sender, instance, **kwargs):
    try:
        instance.userprofile.save()
    except Exception as e:
        logger.error(f"Error saving UserProfile: {e}")


#Signal receiver to notify admin when a user is locked out due to failed login attempts.
@receiver(user_locked_out)
def send_lockout_alert(sender, request, user, ip_address, **kwargs):
    message = (
        f"User {user.username} has been locked out due to too many failed login attempts.\n"
        f"IP Address: {ip_address}"
    )
    send_mail(
        subject="Account Locked Out",
        message=message,
        from_email=settings.EMAIL_HOST_USER, # Sender email (configured in settings)
        recipient_list=['beatkare@gmail.com'], # Admin email address
    )

