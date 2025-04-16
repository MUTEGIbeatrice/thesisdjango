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
import platform
import http.client
import json

@receiver(user_locked_out)
def send_lockout_alert(sender, request, user, ip_address, **kwargs):
    # Extract user agent info
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    
    # Basic parsing of user agent for OS and device type (simplified)
    os_info = "Unknown OS"
    device_type = "Unknown Device"
    if 'Windows' in user_agent:
        os_info = "Windows"
    elif 'Macintosh' in user_agent:
        os_info = "Mac OS"
    elif 'Linux' in user_agent:
        os_info = "Linux"
    elif 'Android' in user_agent:
        os_info = "Android"
    elif 'iPhone' in user_agent or 'iPad' in user_agent:
        os_info = "iOS"
    
    if 'Mobile' in user_agent:
        device_type = "Mobile"
    elif 'Tablet' in user_agent:
        device_type = "Tablet"
    else:
        device_type = "Desktop"
    
    # Attempt to get location info from IP using a free API (ip-api.com)
    location = "Unknown Location"
    try:
        conn = http.client.HTTPConnection("ip-api.com")
        conn.request("GET", f"/json/{ip_address}")
        res = conn.getresponse()
        data = res.read()
        location_data = json.loads(data)
        if location_data.get('status') == 'success':
            city = location_data.get('city', '')
            region = location_data.get('regionName', '')
            country = location_data.get('country', '')
            location = f"{city}, {region}, {country}".strip(', ')
    except Exception as e:
        location = "Location lookup failed"
    
    message = (
        f"User {user.username} has been locked out due to too many failed login attempts.\n"
        f"IP Address: {ip_address}\n"
        f"Location: {location}\n"
        f"Operating System: {os_info}\n"
        f"Device Type: {device_type}\n"
        f"User Agent: {user_agent}\n"
    )
    send_mail(
        subject="Account Locked Out",
        message=message,
        from_email=settings.EMAIL_HOST_USER, # Sender email (configured in settings)
        recipient_list=['beatkare@gmail.com'], # Admin email address
    )

