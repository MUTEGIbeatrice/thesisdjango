from django.urls import path
from .views import security_dashboard

urlpatterns = [
    path('', security_dashboard, name='dashboard'),
    path('security-dashboard/', security_dashboard, name='security_dashboard'),
]
