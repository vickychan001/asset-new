from django.urls import path
from .views import *

urlpatterns = [
    # Asset routes
    path('assets/register/', register_asset, name='register-asset'),
    path('assets/', view_assets, name='view-assets'),
    path('assets/update/<int:pk>/', update_asset, name='update-asset'),
    path('assets/delete/<int:pk>/', delete_asset, name='delete-asset'),

    # Employee routes
    path('employees/register/', register_employee, name='register-employee'),
    path('employees/', view_employees, name='view-employees'),

    # Maintenance record route
    path('maintenance-records/', view_maintenance_records, name='view-maintenance-records'),

    path('managers/register/', register_manager, name='register-manager'),
    path('api/token/', CustomTokenObtainPairView, name='token_obtain_pair'),
    path('api/login/', login, name='manager_login'),
]





