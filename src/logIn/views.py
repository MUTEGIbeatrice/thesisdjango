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
import requests, logging, pyotp, json
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse_lazy
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





# Create your views here.

# Initialize logger
logger = logging.getLogger(__name__)

# Get user model
User = get_user_model()



# logIn  REQUEST, AUTHENTICATION AND RESTRICTION TO AN ALREADY AUTHENTICATED USER
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@unauthenticated_user  # Prevent logged-in users from accessing the login page
def logIn(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        otp = request.POST.get('otp')  # Get OTP input
        hcaptcha_response = request.POST.get('h-recaptcha-response', '').strip()

        # Validate hCaptcha response
        if not verify_hcaptcha(hcaptcha_response):
            messages.error(request, "Please complete the CAPTCHA to proceed.")
            return render(request, "logIn/login.html")

        # Check for account lockout first
        failed_attempts = cache.get(f'failed_attempts_{username}', 0)
        if failed_attempts >= 3:
            logger.warning(f'User {username} locked out due to multiple failed login attempts')
            messages.error(request, "Too many failed login attempts. Your account is locked.")
            return redirect('lockout')

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user:
            if not user.check_password(password):
                failed_attempts += 1
                cache.set(f'failed_attempts_{username}', failed_attempts, timeout=900)
                logger.warning(f'Invalid credentials for user {username}')
                messages.error(request, "Invalid Credentials. Please try again.")
                return render(request, "logIn/login.html")

            # OTP Verification via Email
            if hasattr(user, 'userprofile') and user.userprofile.otp:
                if not otp:
                    otp_code = generate_otp_secret(user)
                    send_otp(user.email, otp_code)
                    messages.info(request, "An OTP has been sent to your email.")
                    return render(request, "logIn/login.html", {"username": username, "resend": True})

                if otp != user.userprofile.otp:
                    failed_attempts += 1
                    if failed_attempts >= 3:
                        user.userprofile.otp = None  # Reset OTP
                        user.userprofile.save()
                    cache.set(f'failed_attempts_{username}', failed_attempts, timeout=900)
                    messages.error(request, "Invalid OTP. Please request a new one.")
                    return render(request, "logIn/login.html", {"username": username, "resend": True})

            # Successful login
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
            user.userprofile.otp = None  # Reset previous OTP
            user.userprofile.save()

            otp_code = generate_otp_secret(user)
            send_otp(user.email, otp_code)

            return JsonResponse({'message': 'OTP resent successfully.'}, status=200)

        except User.DoesNotExist:
            return JsonResponse({'message': 'Invalid username.'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data.'}, status=400)

    return JsonResponse({'message': 'Invalid request method.'}, status=405)

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


# SIGN UP VIEW
def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST, request.FILES)

        if form.is_valid():  # Only check reCAPTCHA if form is valid
            if not validate_hcaptcha(request):  # Use function to verify reCAPTCHA
                return render(request, "logIn/signup.html", {"form": form, "HCAPTCHA_SITE_KEY": settings.HCAPTCHA_SITE_KEY})

            form.save()
            messages.success(request, "Account created successfully! Please log in.")
            return redirect("login")
        else:
            messages.error(request, "There were errors in the form. Please check and try again.")
            logging.error(f"Signup Form Errors: {form.errors}")

    else:
        form = CustomUserCreationForm()

    return render(request, "logIn/signup.html", {"form": form, "HCAPTCHA_SITE_KEY": settings.HCAPTCHA_SITE_KEY})


# PASSWORD CHANGING
# Custom password change view using Django's PasswordChangeView
class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'logIn/passwordchange.html'
    success_url = reverse_lazy('password_change_done')  # Redirect after successful password change



# Password change with CAPTCHA validation
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



#LOCKOUT
def lockOut(request):
    messages.success(request, "Too many failed login attempts. Your account is locked.")
    return render(request, 'logIn/lockout.html')



def contact_support(request):
    if request.method == "POST":
       
        form = SupportMessageForm(request.POST)
        if form.is_valid():
            username = request.user.username if request.user.is_authenticated else form.cleaned_data['nameGuest']
            email = request.user.email if request.user.is_authenticated else form.cleaned_data['emailGuest']
            subject = form.cleaned_data['subject']
            message = form.cleaned_data['message']
            admin_email = "beatkare@gmail.com"  # Change to Django admin's email

            # Format the message to include the username
            full_message = f"User: {username}\nEmail: {email}\n\nMessage:\n{message}"

            # Send an email to admin
            send_mail(
                subject=f"Support Request from {username}: {subject}",
                message=full_message,
                from_email="noreply@example.com",
                recipient_list=[admin_email],
                fail_silently=False,
            )

            messages.success(request, "Your message has been sent.")
            return redirect("login")  # Redirect after success

    else:
        # Prepopulate the form with user data if authenticated
        form = SupportMessageForm(initial={'username': request.user.username, 'email': request.user.email} if request.user.is_authenticated else {})

    return render(request, "logIn/contactsupport.html", {"form": form})


#To notify administrators when someone is locked out.
@receiver(user_locked_out)
def send_lockout_alert(request, username, ip_address, **kwargs):
    send_mail(
        "Account Locked Out",
        f"User {username} has been locked out due to too many failed login attempts.\n"
        f"IP Address: {ip_address}",
        "noreply@example.com",
        ["admin@example.com"],
    )



# Function to verify reCAPTCHA
def verify_hcaptcha(hcaptcha_response):
    secret_key = settings.HCAPTCHA_SECRET_KEY  # hCaptcha secret key
    data = {
        'secret': secret_key,
        'response': hcaptcha_response
    }
    
    # Send the POST request to Google's reCAPTCHA API
    r = requests.post("https://hcaptcha.com/siteverify", data=data)
    
    # Return the verification result
    return r.json().get("success", False)


# Function to handle form submission and validate reCAPTCHA

def validate_hcaptcha(request):
    hcaptcha_response = request.POST.get('h-recaptcha-response')
    if not hcaptcha_response:
        messages.error(request, "Please complete the CAPTCHA verification.")
        return False

    data = {
        'secret': settings.HCAPTCHA_SECRET_KEY,
        'response': hcaptcha_response
    }

    try:
        response = requests.post('https://hcaptcha.com/siteverify', data=data)
        result = response.json()

        if not result.get('success'):
            error_codes = result.get("error-codes", [])
            logging.error(f"hCAPTCHA validation failed: {error_codes}")

            if "timeout-or-duplicate" in error_codes:
                messages.error(request, "hCAPTCHA expired. Please refresh and try again.")
            else:
                messages.error(request, "CAPTCHA verification failed. Please try again.")

            return False  # Return False if validation failed

        return True  # Return True if validation succeeded

    except requests.exceptions.RequestException as e:
        logging.error(f"hCAPTCHA request failed: {e}")
        messages.error(request, "Error verifying CAPTCHA. Please try again.")
        return False
