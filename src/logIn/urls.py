from django.urls import path, include
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
from .views import custom_password_change, CustomPasswordChangeView
from .views import contact_support




urlpatterns = [
    path('',views.logIn, name="login"), 
    path('login/',views.logIn, name="login"), 
    path('logout/',views.logOut, name="logout"),
    path('home/',views.home, name="home"),
    path('signup/',views.signup, name="signup"),
    
    
    # Password Management
    path('passwordchange/', views.CustomPasswordChangeView.as_view(), name='passwordchange'),
    path('passwordchange/done/', auth_views.PasswordChangeDoneView.as_view(template_name='password_change_done.html'), name='password_change_done'),
    path('password_change/', views.custom_password_change, name='password_change'),

    path('lockout/',views.lockOut, name="lockout"),
    path("contactsupport/", contact_support, name="contactsupport"),

    path('resend-otp/', views.resend_otp, name='resend_otp'),  

]