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
from django.contrib.auth.signals import user_login_failed
from .forms import SupportMessageForm
from django.core.mail import send_mail #Sending alert mails
from django.dispatch import receiver
from axes.signals import user_locked_out
from django.contrib.auth.views import PasswordChangeView
from django_otp.forms import OTPAuthenticationForm
from django_otp.plugins.otp_totp.models import TOTPDevice  # To get the OTP device associated with the user
from django_otp.models import Device
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





# Create your views here.

# Initialize logger
logger = logging.getLogger(__name__)

# Get user model
User = get_user_model()



# logIn  REQUEST, AUTHENTICATION AND RESTRICTION TO AN ALREADY AUTHENTICATED USER
# Uses CAPTCHAs to prevent bots.
@ratelimit(key='ip', rate='10/m', method='POST', block=True)  # Account Lockout or Cooldown
@unauthenticated_user  # Prevent logged-in users from accessing the login page
def logIn(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        otp = request.POST.get('otp')
        recaptcha_response = request.POST.get('g-recaptcha-response', '').strip()

        # Validate reCAPTCHA
        if not verify_recaptcha(request, recaptcha_response):
            messages.error(request, "Please complete the CAPTCHA to proceed.")
            return render(request, "logIn/login.html")

        # Account lockout check
        failed_attempts = cache.get(f'failed_attempts_{username}', 0)
        if failed_attempts >= 3:
            logger.warning(f'User {username} locked out due to multiple failed login attempts')
            messages.error(request, "Too many failed login attempts. Your account is locked.")
            return redirect('lockout')

        # User authentication
        user = authenticate(request, username=username, password=password)

        if user:
            if not user.check_password(password):
                failed_attempts += 1
                cache.set(f'failed_attempts_{username}', failed_attempts, timeout=900)
                logger.warning(f'Invalid credentials for user {username}')
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
            request.session.set_expiry(settings.SESSION_COOKIE_AGE)
            return redirect('home')

        else:
            failed_attempts += 1
            cache.set(f'failed_attempts_{username}', failed_attempts, timeout=600)
            logger.warning(f'Failed login attempt for user {username}')
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
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)  # Don't save yet
            user.is_active = False  # Set user to inactive until email is verified

            try:
                # Run password validation before saving the user
                validate_password(user.password, user)
            except ValidationError as e:
                form.add_error('password', e)
                return render(request, "logIn/signup.html", {"form": form})

            user.save()  # Save the user after validation

            
            # Generate UID and token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = email_token_generator.make_token(user)

            # Construct verification URL
            verify_url = request.build_absolute_uri(
                reverse('verify_email', kwargs={'uidb64': uid, 'token': token})
            )

            try:
                # Prepare email context
                context = {
                    'username': user.username,
                    'verify_url': verify_url,
                }
                
                # Render email content from template
                email_content = render_to_string('logIn/email_verification.html', context)
                plain_message = strip_tags(email_content)
                
                # Send email
                send_mail(
                    subject="Verify Your Email",
                    message=plain_message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[user.email],
                    html_message=email_content,
                    fail_silently=False
                )
                logger.info("Verification email sent successfully to %s", user.email)
            except Exception as e:
                logger.error("Failed to send verification email to %s: %s", user.email, str(e))
                messages.error(request, "Failed to send verification email. Please try again later.")
                user.delete()  # Clean up the inactive user
                return redirect('signup')

            messages.success(request, "Check your email (in the inbox, spam or promotion folder) to verify your account.")
            return redirect("login")
    else:
        form = CustomUserCreationForm()

    return render(request, "logIn/signup.html", {"form": form})




# Function to verify emails when signing up
def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and email_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, "logIn/email_verification_success.html")  # Styled success page
    else:
        messages.error(request, "Verification link is invalid or has expired.")
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
    messages.success(request, "You have been logged out.")   
    return redirect('login')  # Redirect to the login page after logout



def contact_support(request):
    if request.method == "POST":
       
        form = SupportMessageForm(request.POST)
        if form.is_valid():
            username = request.user.username if request.user.is_authenticated else form.cleaned_data['nameGuest']
            email = request.user.email if request.user.is_authenticated else form.cleaned_data['emailGuest']
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
        # Prepopulate the form with user data if authenticated
        form = SupportMessageForm(initial={'username': request.user.username, 'email': request.user.email} if request.user.is_authenticated else {})

    return render(request, "logIn/contactsupport.html", {"form": form})



#LOCKOUT
def lockOut(request):
    messages.success(request, "Too many failed login attempts. Your account is locked.")
    return render(request, 'logIn/lockout.html')



#To notify administrators when someone is locked out.
@receiver(user_locked_out)
def send_lockout_alert(request, username, ip_address, **kwargs):
    send_mail(
        "Account Locked Out",
        f"User {username} has been locked out due to too many failed login attempts.\n"
        f"IP Address: {ip_address}",
        "djangoapp2025@gmail.com",
        ["djangoapp2025@gmail.com"],
    )


