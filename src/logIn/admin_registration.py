from django.contrib import admin
from .models import LockoutLog

@admin.register(LockoutLog)
class LockoutLogAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'timestamp')
    search_fields = ('username', 'ip_address')
    list_filter = ('timestamp',)
