from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import UserProfile
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=get_user_model())
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        try:
            UserProfile.objects.get_or_create(user=instance)
            logger.info(f"Created UserProfile for {instance.username}")
        except Exception as e:
            logger.error(f"Error creating UserProfile: {e}")
            raise

@receiver(post_save, sender=get_user_model())
def save_user_profile(sender, instance, **kwargs):
    try:
        instance.userprofile.save()
    except Exception as e:
        logger.error(f"Error saving UserProfile: {e}")
