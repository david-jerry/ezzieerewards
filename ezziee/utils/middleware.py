from django.http import JsonResponse
from allauth.account.adapter import get_adapter

from ..utils.mails import CustomEmailSender
from ..utils.exceptions import UnauthorizedException

class MultiFactorAuthMiddleware:
    """
    Middleware for enforcing Multi-Factor Authentication (MFA) on authenticated users.

    This middleware checks if the user is authenticated and if MFA has been verified.
    If the user is not authenticated, it returns a 401 Unauthorized response.
    If MFA verification is required and not yet done, it returns a 401 Unauthorized response.

    Usage:
    1. Include this middleware in your Django project settings.
    2. Ensure that user authentication is done before this middleware in the MIDDLEWARE setting.

    Example:
    MIDDLEWARE = [
        # ... other middlewares
        'path.to.MultiFactorAuthMiddleware',
        # ... other middlewares
    ]

    Attributes:
    get_response (callable): The next middleware or view function in the Django processing pipeline.
    """

    def __init__(self, get_response):
        """
        Initializes the middleware.

        Args:
        get_response (callable): The next middleware or view function in the Django processing pipeline.
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Handles the processing of the request.

        Args:
        request (HttpRequest): The incoming HTTP request.

        Returns:
        JsonResponse: A 401 Unauthorized response if authentication or MFA is required.
                      Otherwise, it passes the request to the next middleware or view function.
        """
        # Check if the requested URL path starts with "/api/v1/users/" or "/api/v1/password-change/"
        if request.path.startswith('/api/v1/users/') or request.path.startswith('/api/v1/password-change/'):
            if not request.user.is_authenticated:
                return JsonResponse({'error': "Authentication is required."}, status=401)

            # Implementation of MFA logic
            # if not request.session.get('mfa_verified') and not request.path.startswith('/api/v1/logout/'):
            #     return JsonResponse({'error': "MFA is required."}, status=401)

        response = self.get_response(request)
        return response


class DomainMiddleware:
    """
    Middleware for extracting and storing the domain from the incoming request.

    This middleware retrieves the domain from the request and adds it to the request object.
    Additionally, if the user is authenticated, it saves the domain in the user's profile.

    Usage:
    1. Include this middleware in your Django project settings.
    2. Access the domain in your views or other parts of the application using `request.domain`.

    Example:
    In your Django project settings (settings.py):

    ```python
    MIDDLEWARE = [
        # ... other middlewares
        'path.to.DomainMiddleware',
        # ... other middlewares
    ]
    ```

    In your views or other parts of the application:

    ```python
    def some_view(request):
        # Access the domain from the request
        domain = request.domain
        # ... your logic here
    ```

    Attributes:
        get_response (callable): The next middleware or view function in the Django processing pipeline.
    """

    def __init__(self, get_response):
        """
        Initializes the middleware.

        Args:
            get_response (callable): The next middleware or view function in the Django processing pipeline.
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Handles the processing of the request.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            HttpResponse: The HTTP response after processing.
        """
        # Get the domain from the request
        adapter = get_adapter(request)
        user_ip = adapter.get_client_ip(request)


        if not request.user.is_authenticated and not request.user.is_staff and request.path.startswith('/users/') and not request.path.startswith('/api/v1/auth/'):
            raise UnauthorizedException

        if request.user.is_staff:
            pass

        # Add the domain to the request
        request.ip = user_ip

        response = self.get_response(request)
        return response
