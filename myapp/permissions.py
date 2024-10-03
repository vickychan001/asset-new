from rest_framework import permissions
from rest_framework_simplejwt.tokens import AccessToken

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            # Extract token from header
            auth_header = request.headers.get('Authorization')
            print(auth_header)
            if not auth_header:
                return False

            # Remove "Bearer" and decode the token
            token_str = auth_header.split(' ')[1]
            token = AccessToken(str(token_str))
            print(token)

            # Extract the user's role from the token payload
            
            return {
                'user_id': token['user_id'],  # Get user_id from token
                'role': token.get('role', 'undefined')  # Get role if present
            }
        
            
        except Exception as e:
            return False
        

