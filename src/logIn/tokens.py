#Token Expiration Mechanism in signup page

from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from datetime import datetime, timedelta
from django.utils.http import base36_to_int


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{timestamp}{user.is_active}"

    def check_token(self, user, token):
        if not super().check_token(user, token):
            return False

        timestamp = self._parse_token_timestamp(token)
        if not timestamp:
            return False

        token_time = datetime.fromtimestamp(timestamp)
        if datetime.now() - token_time > timedelta(hours=24):  # 24 hours expiry
            return False

        return True

    def _parse_token_timestamp(self, token):
        try:
            ts_b36 = token.split("-")[1]
            ts_int = self._num_from_timestamp(ts_b36)
            return ts_int
        except Exception:
            return None

    def _num_from_timestamp(self, ts_b36):
        from django.utils.http import base36_to_int
        return base36_to_int(ts_b36)

email_token_generator = EmailVerificationTokenGenerator()
