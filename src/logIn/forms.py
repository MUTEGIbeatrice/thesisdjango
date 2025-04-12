
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox # Import reCaptchaWidget
from .utils import generate_otp_secret



class CustomUserCreationForm(UserCreationForm):
    #captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox())
    # Adding extra fields to the form
    first_name = forms.CharField(max_length=30, required=True, widget=forms.TextInput(attrs={'placeholder': 'First Name'}))
    last_name = forms.CharField(max_length=30, required=True, widget=forms.TextInput(attrs={'placeholder': 'Last Name'}))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'placeholder': 'Email Address'}))
    username = forms.CharField(max_length=150, required=True, widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}))

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)  # Create User instance but don't save yet
        user.set_password(self.cleaned_data["password1"])  # Set hashed password

        if commit:
            user.save()  # Save the User instance to the database
            UserProfile.objects.get_or_create(user=user) # Ensure profile is created

        return user


    #email uniqueness check
    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

    

#Google reCAPTCHA for login form
class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox())
    otp = forms.CharField(max_length=6, required=True, widget=forms.TextInput(attrs={'placeholder': 'Enter OTP'}))


#Support Message Form
class SupportMessageForm(forms.Form):
    username = forms.CharField(
        max_length=100, 
        required=True,
        widget=forms.TextInput(attrs={'readonly': 'readonly'})  # Read-only for security
    )
    email = forms.CharField(
        max_length=100, 
        required=True,
        widget=forms.TextInput(attrs={'readonly': 'readonly'})  # Read-only for security
    )
    name = forms.CharField(
        max_length=100, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'name'})  
    )
    emailGuest = forms.CharField(
        max_length=100, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'email'})  
    )
    subject = forms.CharField(
        max_length=100, 
        required=True, 
        widget=forms.TextInput(attrs={'placeholder': 'Subject'})
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Describe your issue'}), 
        required=True
    )