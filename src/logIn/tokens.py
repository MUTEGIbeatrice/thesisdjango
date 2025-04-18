#Token generation utilities for user account activation and password reset.
# Includes functions to create and verify tokens for secure user actions.

from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six, hashlib, logging
from datetime import datetime, timedelta
from django.utils.http import base36_to_int
 


#Custom token generator for email verification (24hrs till token expires).
class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active)
        )

email_token_generator = EmailVerificationTokenGenerator()