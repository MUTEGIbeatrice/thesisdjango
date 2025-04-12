from django.http import HttpResponse
from django.shortcuts import redirect

# FUNCTION DECORATORS TO RESTRICT UNAUTHENTICATED USERS (TO ENABLE ACCESS CONTROL)
def unauthenticated_user(view_func):
    def _wrapped_view(request, *args, **kwargs):
        # Skip for admin login page
        if request.path.startswith('/admin/login/'):
            return view_func(request, *args, **kwargs)

        if request.user.is_authenticated:
            return redirect('home')  # Prevent logged-in users from accessing login
        return view_func(request, *args, **kwargs)
    return _wrapped_view

    

 # FUNCTION DECORATORS FOR AUTHENTICATED USERS (TO ENABLE ACCESS CONTROL AS PER THE USER ROLES)
def allowed_users(allowed_roles=[]):
    def decorator(view_func):
        def wrapper_func(request, *args, **kwargs):

            group = None
            if request.user.groups.exists():
                group = request.user.groups.all()[0].name

            if group and group in allowed_roles:
                return view_func(request, *args, **kwargs)
            else:
                return HttpResponse('You are not authorized to access this page')
        return wrapper_func
    return decorator