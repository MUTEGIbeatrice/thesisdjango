#Django imports
from django.shortcuts import render, redirect 
from django.http import HttpResponse, JsonResponse
from .models import * #FOR IMPORTING ALL MODELS 
from django.conf import settings 
from django.contrib import admin
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash, get_user_model #FOR AUTH AND LOGOUT
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import UserCreationForm #to sign up or register new users
from .forms import CustomUserCreationForm
from django.contrib import messages #FOR ERROR AND INFORMATION/STATUS MESSAGES
from django.contrib.auth.decorators import login_required #FOR ENABLING VIEW RESTRICTIONS UNTIL LOGGED IN 
from datetime import date, timedelta
from django.utils.timezone import now, timedelta
from django.core.cache import cache  # Store failed attempts
from .decorators import unauthenticated_user, allowed_users #FOR IMPORTING THE USER ACCESS CONTROL DECORATORS
import requests, logging, pyotp, json, random
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse_lazy, reverse
from django.utils.crypto import constant_time_compare
from axes.utils import reset
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.contrib.auth.signals import user_login_failed
from .forms import SupportMessageForm
from django.core.mail import send_mail #Sending alert mails
from django.dispatch import receiver
from axes.signals import user_locked_out
from django.contrib.auth.views import PasswordChangeView
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
import time
from .utils import *
from .utils import generate_otp_secret, send_otp
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from .tokens import email_token_generator
from django.db import transaction
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.views.decorators.http import require_GET
from django.utils import timezone
from .models import LockoutLog
from django.db.models import Count
import http.client
import json





# Create your views here.

# Initialize logger
logger = logging.getLogger(__name__)

# Get user model
User = get_user_model()




# logIn  REQUEST, AUTHENTICATION AND RESTRICTION TO AN ALREADY AUTHENTICATED USER
# Uses CAPTCHAs to prevent bots.
#Ratelimiting that combines username+IP limits to prevent distributed attacks
def ratelimit_key_func(group, request):
    username = request.POST.get('username', '')
    ip = request.META.get('REMOTE_ADDR', '')
    return f"{username}:{ip}"

@ratelimit(key=ratelimit_key_func, rate='5/15m', method='POST', block=False)
@unauthenticated_user
def logIn(request):
    from django_ratelimit.exceptions import Ratelimited
    if request.method == 'POST':
        if getattr(request, 'limited', False):
            messages.error(request, "Too many login attempts. Please try again later.")
            return render(request, "logIn/lockout.html")

        username = request.POST.get('username')
        password = request.POST.get('password')
        otp = request.POST.get('otp')
        recaptcha_response = request.POST.get('g-recaptcha-response', '').strip()

        # Validate reCAPTCHA
        if not verify_recaptcha(request, recaptcha_response):
            messages.error(request, "Please complete the CAPTCHA to proceed.")
            return render(request, "logIn/login.html")

        # Account lockout check by username
        failed_attempts = cache.get(f'failed_attempts_{username}', 0)
        ip = request.META.get('REMOTE_ADDR')
        failed_attempts_ip = cache.get(f'failed_attempts_ip_{ip}', 0)

        # Check lockout by username
        if failed_attempts >= 3:
            logger.warning(f'User {username} locked out due to multiple failed login attempts')
            messages.error(request, "Too many failed login attempts. Your account is locked.")
            send_lockout_email(username)

            # Log lockout with user agent, os info, device type
            ip_address = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            import user_agents
            ua = user_agents.parse(user_agent)
            os_info = f"{ua.os.family} {ua.os.version_string}"
            device_type = 'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'PC' if ua.is_pc else 'Other'

            from .models import LockoutLog
            LockoutLog.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                os_info=os_info,
                device_type=device_type,
                is_simulation=False
            )

            return redirect('lockout')

        # Check lockout by IP
        if failed_attempts_ip >= 10:
            logger.warning(f'IP {ip} locked out due to multiple failed login attempts')
            messages.error(request, "Too many failed login attempts from your IP address. Access temporarily blocked.")
            return redirect('lockout')

        # User authentication
        user = authenticate(request, username=username, password=password)

        if user:
            if not user.check_password(password):
                failed_attempts += 1
                failed_attempts_ip += 1
                cache.set(f'failed_attempts_{username}', failed_attempts, timeout=900)
                cache.set(f'failed_attempts_ip_{ip}', failed_attempts_ip, timeout=900)
                logger.warning(f'Invalid credentials for user {username} from IP {ip}')
                messages.error(request, "Invalid Credentials. Please try again.")
                return render(request, "logIn/login.html")

            # OTP Verification
            if hasattr(user, 'userprofile') and user.userprofile.otp:
                if not user.userprofile.is_otp_valid():
                    # OTP expired, clear and prompt for new OTP
                    user.userprofile.otp = None
                    user.userprofile.save()
                    messages.error(request, "Your OTP has expired. Please request a new one.")
                    return render(request, "logIn/login.html")

                if not otp:  # No OTP entered yet; generate and send one
                    from django.utils import timezone
                    otp_code = generate_otp_secret(user)
                    send_otp(user.email, otp_code)

                    # Clear any existing OTP first
                    user.userprofile.otp = None
                    user.userprofile.otp_expiry = None
                    user.userprofile.save()

                    # Set new OTP with proper timezone handling
                    user.userprofile.otp = otp_code
                    user.userprofile.otp_expiry = timezone.localtime(timezone.now()) + timedelta(minutes=10)
                    user.userprofile.save()

                    logger.info(f"Generated OTP for {user.username} at {timezone.localtime(timezone.now())}, expires at {user.userprofile.otp_expiry}")

                    messages.info(request, "An OTP has been sent to your email.")
                    return render(request, "logIn/login.html", {"username": username, "resend": True})

                if otp != user.userprofile.otp:  # Entered OTP does not match
                    failed_attempts += 1

                    if failed_attempts >= 3:  # Lock account after multiple failed attempts
                        user.userprofile.otp = None  # Reset stored OTP
                        user.userprofile.save()
                        cache.set(f'failed_attempts_{username}', failed_attempts, timeout=900)  # Lock for 15 minutes

                        messages.error(request, "Invalid OTP. Please request a new one.")
                        return render(request, "logIn/login.html", {"username": username, "resend": True})

            # Login successful
            logger.info(f'User {username} logged in successfully')
            messages.success(request, 'Login Successful')
            login(request, user)
            cache.delete(f'failed_attempts_{username}')
            cache.delete(f'failed_attempts_ip_{ip}')
            request.session.set_expiry(settings.SESSION_COOKIE_AGE)
            return redirect('home')

        else:
            failed_attempts += 1
            failed_attempts_ip += 1
            cache.set(f'failed_attempts_{username}', failed_attempts, timeout=600)
            cache.set(f'failed_attempts_ip_{ip}', failed_attempts_ip, timeout=600)
            logger.warning(f'Failed login attempt for user {username} from IP {ip}')
            messages.error(request, "Invalid Credentials. Please try again.")
            return render(request, "logIn/login.html")

    return render(request, "logIn/login.html")



def send_lockout_email(username):
    from django.core.mail import send_mail
    from django.conf import settings
    try:
        user = User.objects.get(username=username)
        send_mail(
            subject="Account Locked Due to Multiple Failed Login Attempts",
            message=f"Dear {user.username if user else 'User Unknown'},\n\nYour account has been temporarily locked due to multiple failed login attempts. Please try again after some time or contact support if this wasn't you.",
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email] if user else [settings.EMAIL_HOST_USER],
            fail_silently=True,
        )
        logger.info(f"Lockout notification email sent to {user.email if user else 'admin'}")
    except User.DoesNotExist:
        logger.warning(f"Attempted to send lockout email to non-existent user {username}")

            # Login successful
        logger.info(f'User {username} logged in successfully')
        messages.success(request, 'Login Successful')
        login(request, user)
        cache.delete(f'failed_attempts_{username}')
        cache.delete(f'failed_attempts_ip_{ip}')
        request.session.set_expiry(settings.SESSION_COOKIE_AGE)
        return redirect('home')

    else:
        failed_attempts += 1
        failed_attempts_ip += 1
        cache.set(f'failed_attempts_{username}', failed_attempts, timeout=600)
        cache.set(f'failed_attempts_ip_{ip}', failed_attempts_ip, timeout=600)
        logger.warning(f'Failed login attempt for user {username} from IP {ip}')
        messages.error(request, "Invalid Credentials. Please try again.")
        return render(request, "logIn/login.html")

    return render(request, "logIn/login.html")



# Resend OTP
def resend_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')

            if not username:
                return JsonResponse({'message': 'Username is required.'}, status=400)

            user = User.objects.get(username=username)
            
            # Reset OTP and expiry
            user.userprofile.otp = None
            user.userprofile.otp_expiry = None
            user.userprofile.save()

            # Generate and send new OTP
            otp_code = generate_otp_secret(user)
            send_otp(user.email, otp_code)

            return JsonResponse({
                'message': 'OTP resent successfully.',
                'status': 'success'
            }, status=200)
            
        except User.DoesNotExist:
            return JsonResponse({
                'message': 'Invalid username.',
                'status': 'error'
            }, status=400)
            
        except Exception as e:
            logger.error(f"Failed to resend OTP: {str(e)}")
            return JsonResponse({
                'message': 'Failed to resend OTP. Please try again.',
                'status': 'error'
            }, status=500)


            
# Function to verify Google reCAPTCHA
def verify_recaptcha(request, recaptcha_response):
    secret_key = settings.RECAPTCHA_PRIVATE_KEY  # Google reCAPTCHA secret key
    data = {
        'secret': secret_key,
        'response': recaptcha_response
    }

    try:
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()

        if not result.get('success'):
            error_codes = result.get("error-codes", [])
            logging.error(f"reCAPTCHA validation failed: {error_codes}")

            if "timeout-or-duplicate" in error_codes:
                messages.error(request, "reCAPTCHA expired. Please refresh and try again.")
            else:
                messages.error(request, "CAPTCHA verification failed. Please try again.")

            return False  # Return False if validation failed

        return True  # Return True if validation succeeded

    except requests.exceptions.RequestException as e:
        logging.error(f"reCAPTCHA request failed: {e}")
        messages.error(request, "Error verifying CAPTCHA. Please try again.")
        return False



#Home page view
@login_required(login_url='login')   # RESTRICTION ON UNAUTHENTICATED USERS AND DERIVED FROM 'IMPORT LOGIN_REQUIRED'
def home(request):
    #Enforce Password Expiry
    password_age = (now() - request.user.date_joined).days

    if password_age > settings.PASSWORD_EXPIRE_DAYS :
        messages.warning(request, "Your password has expired. Please change it.")
        return redirect('passwordchange')  # Redirect to change password page

    # Enforce session timeout based on inactivity
    last_activity = request.session.get('last_activity', now().timestamp())
    if now().timestamp() - last_activity > settings.SESSION_COOKIE_AGE:
        messages.warning(request, "Session expired due to inactivity. Please log in again.")
        logout(request)
        return redirect('login')

    # Update last activity timestamp
    request.session['last_activity'] = now().timestamp()

    return render(request, "logIn/home.html")




# SIGN UP VIEW (uses email verification to prevent bots)
def signup(request):
    if request.method == 'POST':
        # Instantiate form with POST data but do not validate yet
        form = CustomUserCreationForm(request.POST)
        try:
            # Create user instance but do not save yet
            user = form.save(commit=False)
            # Mark user as inactive until email is verified
            user.is_active = False
            # Save user to database early to avoid unsaved user warning
            user.save()

            # Now validate the form with saved user instance
            if form.is_valid():
                # Create associated user profile if it doesn't exist
                if not hasattr(user, 'userprofile'):
                    UserProfile.objects.create(user=user)

                # Send verification email
                try:
                    verify_email(request, user, form.cleaned_data.get('email'))
                    messages.success(request,
                        f'Dear {user.username},'
                        f'To complete your registration, please check your email {form.cleaned_data.get("email")}'
                        f'(including spam and promotion folder) for the activation link.')
                except Exception as e:
                    logger.error(f"Failed to send verification email: {str(e)}")
                    messages.error(request, "Account created but failed to send verification email. Please contact support.")

            else:
                # Log form validation errors
                logger.error(f"Form validation failed: {form.errors}")
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")

        except Exception as e:
            # Log detailed error for debugging
            logger.error(f"Error during signup: {str(e)}", exc_info=True)
            messages.error(request,
                "An error occurred during registration. Please try again.")
            return render(request, "logIn/signup.html", {"form": form})

    else:
        # GET request - show empty form
        form = CustomUserCreationForm()

    return render(request, "logIn/signup.html", {"form": form})



#Sends email verification link to new user.
def verify_email(request, user, to_email):
    mail_subject = "Activate your user account."
    
    # Build verification URL
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = email_token_generator.make_token(user)
    verify_url = f"{'https' if request.is_secure() else 'http'}://{get_current_site(request).domain}{reverse('activate', kwargs={'uidb64': uid, 'token': token})}"

    # Render email template with context
    message = render_to_string("logIn/email_verification.html", {
        'user': user.username,
        'verify_url': verify_url,
        'domain': get_current_site(request).domain,
        'uid': uid,
        'token': token,
        'protocol': 'https' if request.is_secure() else 'http'
    })
    
    # Create email message
    email = EmailMessage(
        mail_subject,
        message,
        settings.EMAIL_HOST_USER,  # From address
        [to_email]  # Recipient list
    )
    
    try:
        # Attempt to send email
        if email.send():
            messages.success(request, 
                f'Dear {user.username},' 
                f'To complete your registration, please check your email {to_email}'
                f'(including spam folder) for the activation link.')
        else:
            raise Exception("Email sending failed silently")
            
    except Exception as e:
        logger.error(f"Failed to send verification email to {to_email}: {str(e)}")
        messages.error(request, 
            f'Problem sending email to {to_email}. Please verify your email address.')



#To activate/verify email during signup
def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and email_token_generator.check_token(user, token):
        if not user.is_active:  # Only activate if not already active
            user.is_active = True
            user.save()
            messages.success(request, "Email Confirmed Successfully.")
            return redirect('email_verification_success')
        else:
            messages.info(request, "Your account is already active.")
            return redirect('login')
    else:
        messages.error(request, "Invalid activation link - it may have expired or been used already.")
        return redirect('signup')



# PASSWORD CHANGING
# Custom password change view using Django's PasswordChangeView
class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'logIn/passwordchange.html'
    success_url = reverse_lazy('password_change_done')  # Redirect after successful password change




# Password change 
@login_required
def custom_password_change(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)  # Prevents logout after password change
            
            messages.success(request, "Your password has been changed successfully.")
            return redirect('password_change_done')
        else:
            messages.error(request, "Please correct the errors below.")

    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'logIn/passwordchange.html', {'form': form})




#Logout Request
def logOut(request): 
    logout(request)  # Logs out the user
    messages.success(request, "You have successfully logged out.")   
    return redirect('login')  # Redirect to the login page after logout


#for contact support
def contact_support(request):
    if request.method == "POST":
       
        form = SupportMessageForm(request.POST)
        if form.is_valid():
            username = request.user.username if request.user.is_authenticated else form.cleaned_data['username']
            email = request.user.email if request.user.is_authenticated else form.cleaned_data['email']
            subject = form.cleaned_data['subject']
            message = form.cleaned_data['message']
            admin_email = "djangoapp2025@gmail.com"  # Django admin's email

            # Format the message to include the username
            full_message = f"User: {username}\nEmail: {email}\n\nMessage:\n{message}"

            # Send an email to admin
            send_mail(
                subject=f"Support Request from {username}: {subject}: {email}",
                message=full_message,
                from_email="djangoapp2025@gmail.com",
                recipient_list=[admin_email],
                fail_silently=False,
            )

            messages.success(request, "Your message has been sent.")
            return redirect("login")  # Redirect after success
        else:
            # Form is invalid, render with errors
            messages.error(request, "Please correct the errors below.")
            return render(request, "logIn/contactsupport.html", {"form": form})

    else:
        # Prepopulate the form with user data if authenticated
        form = SupportMessageForm(initial={'username': request.user.username, 'email': request.user.email} if request.user.is_authenticated else {})

    return render(request, "logIn/contactsupport.html", {"form": form})



#LOCKOUT
def lockOut(request):
    messages.success(request, "Too many failed login attempts. Your account is locked.")
    return render(request, 'logIn/lockout.html')



# Lockout statistics view
#@staff_member_required  #To be accessible by admin staff members
@login_required
def lockout_stats(request):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access the lockout statistics.")
        return redirect('home')

    # Get top 10 most locked out users
    top_locked_users = LockoutLog.objects.values('username').annotate(
        total_lockouts=Count('id')
    ).order_by('-total_lockouts')[:10]

    # Get lockout counts by hour
    hourly_lockouts = LockoutLog.objects.extra(
        {'hour': "strftime('%%Y-%%m-%%d %%H:00:00', timestamp)"}
    ).values('hour').annotate(
        count=Count('id')
    ).order_by('hour')

    # Get detailed lockout records with additional info
    detailed_lockouts_raw = LockoutLog.objects.values(
        'username', 'timestamp', 'ip_address', 'user_agent', 'os_info', 'device_type', 'is_simulation'
    ).order_by('-timestamp')

    detailed_lockouts = []
    for record in detailed_lockouts_raw:
        ip_address = record.get('ip_address')
        user_agent = record.get('user_agent') or 'Unknown'
        timestamp = record.get('timestamp')
        is_simulation = record.get('is_simulation', False)  # Check if it's a simulation

        if timestamp and timezone.is_naive(timestamp):
            timestamp = timezone.make_aware(timestamp, timezone.get_current_timezone())

        os_info = record.get('os_info') or "Unknown OS"
        device_type = record.get('device_type') or "Unknown Device"

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
        except Exception:
            location = "Location lookup failed"

        detailed_lockouts.append({
            'username': record.get('username'),
            'timestamp': timestamp,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'os_info': os_info,
            'device_type': device_type,
            'location': location,
            'is_simulation': is_simulation,  # Include simulation status
        })

    context = {
        'total_lockouts': LockoutLog.objects.count(),
        'top_locked_users': top_locked_users,
        'hourly_lockouts': hourly_lockouts,
        'detailed_lockouts': detailed_lockouts,
    }
    return render(request, 'logIn/lockout_stats.html', context)