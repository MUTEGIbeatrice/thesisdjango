from django.contrib import admin
from axes.models import AccessAttempt, AccessLog
from .models import LockoutLog, UserProfile
from django.urls import path
from .views import lockout_stats

class DefaultAdminSiteWithLockoutStats(admin.AdminSite):
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('lockout-stats/', self.admin_view(lockout_stats), name='lockout-stats'),
        ]
        return custom_urls + urls

# Note: The view lockout_stats should render 'logIn/lockout_stats.html' template (not 'lockout_statistics.html')

# Replace the default admin site with the subclass instance
admin.site = DefaultAdminSiteWithLockoutStats()

# Register models with the new default admin site
class LockoutLogAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'timestamp')
    search_fields = ('username', 'ip_address')
    list_filter = ('timestamp',)

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'otp_expiry')
    search_fields = ('user__username',)

from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

admin.site.register(User, UserAdmin)
admin.site.register(LockoutLog, LockoutLogAdmin)
admin.site.register(UserProfile, UserProfileAdmin)

