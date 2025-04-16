from django.urls import path, include
from dashboard.views import security_dashboard
from django.contrib import admin
from . import views
from django.contrib.auth import views as auth_views
from django.shortcuts import render, redirect #to allow redirection from one page to another pages
from django.http import HttpResponse #FOR HTTP RESPONSE
from django.contrib.auth.models import User #FOR IMPORTING USERS DATABASE
from django.contrib.auth import authenticate, login, logout #FOR AUTH AND LOGOUT
from django.contrib.auth.models import Group #FOR IMPORTING USERS GROUP MODELS
from django.contrib import messages #FOR ERROR AND INFORMATION/STATUS MESSAGES 
from django.contrib.auth.decorators import login_required #FOR ENABLING VIEW RESTRICTIONS UNTIL LOGGED IN 
from datetime import date, timedelta
from django.views.generic import TemplateView
from .views import custom_password_change, CustomPasswordChangeView
from .views import contact_support




urlpatterns = [
    #URL for Login, Logout, Home, Signup pages
    path('',views.logIn, name="login"), 
    path('login/',views.logIn, name="login"), 
    path('logout/',views.logOut, name="logout"),
    path('home/',views.home, name="home"),
    path('signup/',views.signup, name="signup"),
    
    
    # URL for Password Management
    path('passwordchange/', views.CustomPasswordChangeView.as_view(), name='passwordchange'),
    path('passwordchange/done/', auth_views.PasswordChangeDoneView.as_view(template_name='password_change_done.html'), name='password_change_done'),
    path('password_change/', views.custom_password_change, name='password_change'),
    

    # URL for lockout mechanism and contact support 
    path('lockout/',views.lockOut, name="lockout"),
    path("contactsupport/", contact_support, name="contactsupport"),


    # URL for OTP and Sign up email activation link
    path('resend-otp/', views.resend_otp, name='resend_otp'),  
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('email-verification-success/', TemplateView.as_view(template_name='logIn/email_verification_success.html'), name='email_verification_success'),
    path('admin/lockout-stats/', views.lockout_stats, name='lockout_stats'),
    path('dashboard/security-dashboard/', security_dashboard, name='security_dashboard'),


]