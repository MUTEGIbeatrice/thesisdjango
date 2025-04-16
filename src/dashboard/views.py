from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count, Q, Max
from logIn.models import LockoutLog
import json
from datetime import datetime, timedelta
from django.utils import timezone
import http.client
import json
from django.contrib import messages
from django.shortcuts import redirect



#@staff_member_required  #to be accessible only by admin or staff member
@login_required
def security_dashboard(request):
    # Time period for analysis (last 30 days)
    time_threshold = timezone.now() - timedelta(days=30)
    
    # 1. Failed Login Heatmap - SQLite compatible date extraction
    heatmap_data = (
        LockoutLog.objects
        .filter(timestamp__gte=time_threshold)
        .extra({'date': "strftime('%%Y-%%m-%%d', timestamp)"})
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    
    # 2. IP Threat Analysis (Top 10)
    ip_threats_raw = (
        LockoutLog.objects
        .filter(timestamp__gte=time_threshold)
        .values('ip_address')
        .annotate(
            attempts=Count('id'),
            last_attempt=Max('timestamp')
        )
        .order_by('-attempts')[:10]
    )
    
    ip_threats = []
    for ip_record in ip_threats_raw:
        ip_address = ip_record['ip_address']
        attempts = ip_record['attempts']
        last_attempt = ip_record['last_attempt']
        if last_attempt and timezone.is_naive(last_attempt):
            last_attempt = timezone.make_aware(last_attempt, timezone.get_current_timezone())

        # Get most recent user agent for this IP
        latest_log = LockoutLog.objects.filter(ip_address=ip_address).order_by('-timestamp').first()
        user_agent = latest_log.user_agent if latest_log and hasattr(latest_log, 'user_agent') else 'Unknown'

        # Parse OS and device type from user agent
        os_info = "Unknown OS"
        device_type = "Unknown Device"
        if 'Windows' in user_agent:
            os_info = "Windows"
        elif 'Macintosh' in user_agent:
            os_info = "Mac OS"
        elif 'Linux' in user_agent:
            os_info = "Linux"
        elif 'Android' in user_agent:
            os_info = "Android"
        elif 'iPhone' in user_agent or 'iPad' in user_agent:
            os_info = "iOS"

        if 'Mobile' in user_agent:
            device_type = "Mobile"
        elif 'Tablet' in user_agent:
            device_type = "Tablet"
        else:
            device_type = "Desktop"

        # Get location from IP using ip-api.com
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

        ip_threats.append({
            'ip_address': ip_address,
            'attempts': attempts,
            'last_attempt': last_attempt,
            'user_agent': user_agent,
            'os_info': os_info,
            'device_type': device_type,
            'location': location,
        })
    
    # 3. Security Effectiveness Metrics
    total_attempts = LockoutLog.objects.count()
    # Blocked attempts: count of lockouts with attempts >= 3 or IP in top threats
    blocked_attempts = LockoutLog.objects.filter(
        ip_address__in=[ip['ip_address'] for ip in ip_threats]
    ).count()
    
    # Calculate CAPTCHA fail rate (dummy example, replace with real logic if available)
    captcha_fail_count = LockoutLog.objects.filter(captcha_failed=True).count() if hasattr(LockoutLog, 'captcha_failed') else 0
    captcha_fail_rate = f"{(captcha_fail_count / total_attempts * 100):.1f}%" if total_attempts else "0%"
    
    security_metrics = {
        'total_attempts': total_attempts,
        'blocked_attempts': blocked_attempts,
        'success_rate': f"{((total_attempts - blocked_attempts)/total_attempts)*100:.1f}%" if total_attempts else "0%",
        'time_period': "Last 30 Days",
        'captcha_fail_rate': captcha_fail_rate
    }
    
    context = {
        'heatmap_data': json.dumps(list(heatmap_data)),
        'ip_threats': ip_threats,
        'security_metrics': security_metrics
    }
    return render(request, 'dashboard/security_dashboard.html', context)
