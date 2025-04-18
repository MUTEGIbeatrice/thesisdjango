
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox # Import reCaptchaWidget
from .utils import generate_otp_secret
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


    
    #Extends UserCreationForm with: Email field validation, Password strength requirements, Custom error messages
class CustomUserCreationForm(UserCreationForm):
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

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password1")
        user = self.instance

        # Validate password with user instance only if user is saved (has pk)
        if user.pk:
            from django.contrib.auth.password_validation import validate_password
            try:
                validate_password(password, user)
            except ValidationError as e:
                self.add_error('password1', e)
        return cleaned_data


    #checks if email is unique 
    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email


#Checks password validation
    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("Passwords don't match"))

        # Validate password strength only if user instance is saved
        user = self.instance
        if user.pk:
            from django.contrib.auth.password_validation import validate_password
            try:
                validate_password(password2, user)
            except ValidationError as e:
                raise ValidationError(e)

        return password2
    

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
        widget=forms.TextInput(attrs={'placeholder': 'Enter your username'})  # Allow input
    )
    email = forms.CharField(
        max_length=100, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Enter your email'})  # Allow input
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
