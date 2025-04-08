from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver
from .models import UserProfile
import logging


# Initialize logger
logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """ Create a user profile whenever a new user is created. """
    if created:
        UserProfile.objects.create(user=instance)
        logger.info(f"User profile created for {instance.username}")

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """ Save the user profile whenever the user instance is saved. """
    try:
        instance.userprofile.save()
        logger.info(f"User profile saved for {instance.username}")
    except UserProfile.DoesNotExist:
        UserProfile.objects.create(user=instance)
        logger.info(f"User profile created for {instance.username}")
