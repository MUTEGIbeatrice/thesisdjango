#Token generation utilities for user account activation and password reset.
# Includes functions to create and verify tokens for secure user actions.

from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from datetime import datetime, timedelta
from django.utils.http import base36_to_int
import hashlib


#Custom token generator for email verification.
class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
#Create a hash value for the token based on user information and timestamp.
    def _make_hash_value(self, user, timestamp): 

        return (
            six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active)
        )

email_token_generator = EmailVerificationTokenGenerator()
