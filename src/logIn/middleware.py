from django.shortcuts import redirect
from django.urls import reverse
import logging

logger = logging.getLogger(__name__)

class ExcludeAdminLoginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        logger.info(f"Middleware triggered: Path = {request.path}")

        # Ensure request.user exists before using it
        if not hasattr(request, 'user'):
            logger.warning("request.user does not exist yet!")
            return self.get_response(request)

        logger.info(f"User Authenticated: {request.user.is_authenticated}")

        # Allow access to /admin/ without forcing LOGIN_URL redirect
        if request.path.startswith('/admin/'):
            logger.info("Admin access granted.")
            return self.get_response(request)

        # Redirect unauthenticated users trying to access protected pages
        if not request.user.is_authenticated and request.path != reverse('login'):
            logger.info("Redirecting to login page.")
            return redirect(reverse('login'))

        return self.get_response(request)