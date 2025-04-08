from django.apps import AppConfig


class LoginConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'logIn'

    def ready(self):
        import logIn.signals  # Import the signals when the app is ready
