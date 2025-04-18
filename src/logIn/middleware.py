from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from .models import LockoutLog
from ipware import get_client_ip
import user_agents

class LockoutLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Check if user is locked out (this depends on your lockout logic, here assumed to be in session or cache)
        # For demonstration, let's assume a flag in session 'is_locked_out'
        if request.session.get('is_locked_out', False):
            username = request.user.username if request.user.is_authenticated else 'Unknown'
            ip_address = get_client_ip(request)[0] or '0.0.0.0'
            ua_string = request.META.get('HTTP_USER_AGENT', '')
            ua = user_agents.parse(ua_string)
            os_info = f"{ua.os.family} {ua.os.version_string}"
            device_type = 'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'PC' if ua.is_pc else 'Other'
            user_agent = ua_string

            # Create LockoutLog entry
            LockoutLog.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                os_info=os_info,
                device_type=device_type,
                is_simulation=False
            )
            return HttpResponseForbidden("You are locked out due to multiple failed login attempts.")
        return None
