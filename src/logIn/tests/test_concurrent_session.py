import pytest
from django.contrib.auth.models import User
from django.test import Client
from logIn.models import UserProfile
from django.contrib.sessions.models import Session
from unittest.mock import patch
from django.test import Client, RequestFactory
from logIn.middleware import ConcurrentSessionMiddleware


@pytest.mark.django_db
@patch('logIn.views.verify_recaptcha', return_value=True)
def test_concurrent_session_prevention(mock_verify_recaptcha):
    # Create user
    user = User.objects.create_user(username='testuser2', password='testpass123')
    # Use get_or_create to avoid IntegrityError if UserProfile already exists
    UserProfile.objects.get_or_create(user=user)

    client1 = Client()
    client2 = Client()
    factory = RequestFactory()
    # Middleware requires get_response argument in constructor
    middleware = ConcurrentSessionMiddleware(get_response=lambda request: None)

    # Login with client1
    login1 = client1.post('/login/', {'username': 'testuser2', 'password': 'testpass123'})
    assert login1.status_code == 302  # Redirect on success

    # Get session key after login1
    session_key1 = client1.session.session_key
    user_profile = UserProfile.objects.get(user=user)
    assert user_profile.current_session_key == session_key1

    # Login with client2 (simulate concurrent login)
    login2 = client2.post('/login/', {'username': 'testuser2', 'password': 'testpass123'})
    assert login2.status_code == 302  # Redirect on success

    # Get session key after login2
    session_key2 = client2.session.session_key
    user_profile.refresh_from_db()
    assert user_profile.current_session_key == session_key2
    assert session_key1 != session_key2

    # Now client1 makes a request, simulate middleware check
    request = factory.get('/home/')
    request.user = user
    request.session = client1.session
    response = middleware.process_request(request)
    # If middleware returns a response, it means session invalidated
    if response:
        assert response.status_code in [302, 403]
    else:
        # No response means session valid, so test fails
        assert False, "Concurrent session middleware did not invalidate old session"

    # Client2 should still have access
    response2 = client2.get('/home/')
    assert response2.status_code == 200
