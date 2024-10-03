from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import *
from .serializer import *
from .permissions import IsManager
from rest_framework.exceptions import PermissionDenied
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import AccessToken

@swagger_auto_schema(
    method='post',
    request_body=AssetSerializer,
    responses={201: AssetSerializer, 400: 'Bad Request'},
    operation_description="Register a new asset (Manager only)"
)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, IsManager])
def register_asset(request):
    token = AccessToken(request.headers.get('Authorization').split(' ')[1])
    manager_id = token['user_id']
    # Prepare the data for the new employee
    data = request.data.copy()
    data['manager'] = manager_id  # Associate the new employee with the logged-in manager

    serializer = AssetSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    responses={200: AssetSerializer(many=True), 403: 'Forbidden'},
    operation_description="View assets (Manager views all, Employee views own assets)"
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsManager])
def view_assets(request):
    # Decode the token to get the user (either manager or employee)
    token = AccessToken(str(request.headers.get('Authorization').split(' ')[1]))
    user_id = token['user_id']

    try:
        user = Employee.objects.get(id=user_id)
    except Employee.DoesNotExist:
        return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    if user.role == 'employee':
        # If the user is an employee, return only their own assets
        assets = Asset.objects.filter(employee=user)
    elif user.role == 'manager':
        # If the user is a manager, return all assets of the employees they manage
        employees_under_manager = Employee.objects.filter(manager=user)
        assets = Asset.objects.filter(employee__in=employees_under_manager)
    else:
        return Response({'detail': 'Invalid role.'}, status=status.HTTP_400_BAD_REQUEST)

    # Serialize and return the assets
    serializer = AssetSerializer(assets, many=True)
    return Response({'Assets': serializer.data}, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='put',
    request_body=AssetSerializer,
    responses={200: AssetSerializer, 404: 'Asset Not Found', 403: 'Forbidden'},
    operation_description="Update an existing asset (Manager only)"
)
@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated, IsManager])
def update_asset(request, pk):
    # Extract the token and decode to get the manager ID
    token = AccessToken(request.headers.get('Authorization').split(' ')[1])
    manager_id = token['user_id']
    
    # Verify that the user is a manager
    try:
        manager = Employee.objects.get(id=manager_id)
        if manager.role != 'manager':
            return Response({'detail': 'Only managers can perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    except Employee.DoesNotExist:
        return Response({'detail': 'Manager not found.'}, status=status.HTTP_404_NOT_FOUND)
    # Check if the asset exists and belongs to an employee under the logged-in manager
    try:
        asset = Asset.objects.get(id=pk, employee__manager=manager)
    except Asset.DoesNotExist:
        return Response({'detail': 'Asset not found or not under your management.'}, status=status.HTTP_404_NOT_FOUND)

    serializer = AssetSerializer(asset, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({'detail': 'Asset updated successfully.', 'asset': serializer.data}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='delete',
    responses={204: 'No Content', 404: 'Asset Not Found', 403: 'Forbidden'},
    operation_description="Delete an asset (Manager only)"
)
@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated, IsManager])
def delete_asset(request, pk):
    # Extract the token and decode to get the manager ID
    token = AccessToken(request.headers.get('Authorization').split(' ')[1])
    manager_id = token['user_id']
    
    # Verify that the user is a manager
    try:
        manager = Employee.objects.get(id=manager_id)
        if manager.role != 'manager':
            return Response({'detail': 'Only managers can perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    except Employee.DoesNotExist:
        return Response({'detail': 'Manager not found.'}, status=status.HTTP_404_NOT_FOUND)
    # Check if the asset exists and belongs to an employee under the logged-in manager
    try:
        asset = Asset.objects.get(id=pk, employee__manager=manager)
    except Asset.DoesNotExist:
        return Response({'detail': 'Asset not found or not under your management.'}, status=status.HTTP_404_NOT_FOUND)

    asset.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@csrf_exempt
@swagger_auto_schema(
    method='post',
    request_body=EmployeeSerializer,
    responses={201: EmployeeSerializer, 400: 'Bad Request'},
    operation_description="Register a new employee (Manager only)"
)
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, IsManager])  # Ensure the user is authenticated and is a manager
def register_employee(request):
    # Extract the token and decode it to get the manager ID
    token = request.headers.get('Authorization').split(' ')[1]
    decoded_token = AccessToken(str(token))
    manager_id = decoded_token['user_id']
    print(token)
    print(f"Decoded token - Manager ID: {manager_id}")  # Debugging
    
    # Ensure the user is a manager before proceeding
    try:
        manager = Employee.objects.get(id=manager_id)
        if manager.role != 'manager':
            return Response({'detail': 'Only managers can register employees.'}, status=status.HTTP_403_FORBIDDEN)
    except Employee.DoesNotExist:
        return Response({'detail': 'Manager not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Prepare the data for the new employee
    data = request.data.copy()
    # Validate and save the employee
    serializer = EmployeeSerializer(data=data,context={'manager': manager})
    if serializer.is_valid():
        serializer.save()
        return Response({'detail': 'Employee registered successfully.', 'employee': serializer.data}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='get',
    responses={200: EmployeeSerializer(many=True), 403: 'Forbidden'},
    operation_description="View employees (Manager views own employees, Employee views own data)"
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsManager])
def view_employees(request):
    # Decode the token to get the user ID and role
    token = request.headers.get('Authorization').split(' ')[1]
    decoded_token = AccessToken(str(token))
    user_id = decoded_token['user_id']
    
    
    try:
        logged_in_user = Employee.objects.get(id=user_id)
    except Employee.DoesNotExist:
        return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    # If the logged-in user is a manager, show employees under them
    if logged_in_user.role == 'manager':
        employees = Employee.objects.filter(manager=logged_in_user)
        serializer = EmployeeSerializer(employees, many=True)
        return Response({'employees': serializer.data}, status=status.HTTP_200_OK)
    
    # If the logged-in user is an employee, show only their own details
    elif logged_in_user.role == 'employee':
        serializer = EmployeeSerializer(logged_in_user)
        return Response({'employee': serializer.data}, status=status.HTTP_200_OK)
    
    return Response({'detail': 'Invalid role.'}, status=status.HTTP_403_FORBIDDEN)




@swagger_auto_schema(
    method='get',
    responses={200: MaintenanceRecordSerializer(many=True), 403: 'Forbidden'},
    operation_description="View maintenance records (Manager views all, Employee views own asset records)"
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsManager])
def view_maintenance_records(request,pk):
    # Extract the token and decode to get the employee ID
    token = AccessToken(request.headers.get('Authorization').split(' ')[1])
    employee_id = token['user_id']

    # Verify that the user is an employee
    try:
        employee = Employee.objects.get(id=employee_id)
        if employee.role != 'employee':
            return Response({'detail': 'Only employees can view maintenance records.'}, status=status.HTTP_403_FORBIDDEN)
    except Employee.DoesNotExist:
        return Response({'detail': 'Employee not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Check if the asset exists and is assigned to the logged-in employee
    try:
        asset = Asset.objects.get(id=pk, employee=employee)
    except Asset.DoesNotExist:
        return Response({'detail': 'Asset not found or not assigned to you.'}, status=status.HTTP_404_NOT_FOUND)

    # Fetch the maintenance records for the asset
    maintenance_records = MaintenanceRecord.objects.filter(asset=asset)

    # Serialize the maintenance records and return the response
    serializer = MaintenanceRecordSerializer(maintenance_records, many=True)
    return Response({'maintenance_records': serializer.data}, status=status.HTTP_200_OK)





# Only superuser or admin can register managers
@swagger_auto_schema(
    method='post',
    request_body=ManagerSerializer,
    responses={201: EmployeeSerializer, 400: 'Bad Request', 403: 'Permission Denied'},
    operation_description="Register a new manager (Admin or Superuser only)"
)
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def register_manager(request):
    if not request.user.is_superuser:
        raise PermissionDenied("Only admins or superusers can register managers.")
    
    # Check that the role is set as 'manager'
    data = request.data.copy()  # Create a mutable copy of request data
    data['role'] = 'manager'  # Force the role to be 'manager'

    serializer = ManagerSerializer(data=data)
    if serializer.is_valid():
        serializer.save()  # Save the manager with 'manager' role
        return Response({
            'detail': 'Manager registered successfully.',
            'manager': serializer.data
        }, status=201)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(methods=['post'], request_body=EmployeeLoginSerializer)
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    serializer = EmployeeLoginSerializer(data=request.data)
    if serializer.is_valid():
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework_simplejwt.views import TokenObtainPairView
from .serializer import CustomTokenObtainPairSerializer
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt

@swagger_auto_schema(
    method='post',
    request_body=CustomTokenObtainPairSerializer,
    responses={
        200: openapi.Response('Successful login', CustomTokenObtainPairSerializer),
        400: 'Invalid credentials or not a superuser',
    },
    operation_summary="Obtain access and refresh tokens for superuser",
)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def CustomTokenObtainPairView(request):
    serializer = CustomTokenObtainPairSerializer(data=request.data)
    if serializer.is_valid():
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)