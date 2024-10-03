from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import *
from django.contrib.auth.hashers import make_password

class ManagerSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True,required=True)
    class Meta:
        model = Employee
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'hire_date', 'role', 'password']
        extra_kwargs = {
            'role': {'default': 'manager'} , # Ensure role is always 'manager' 
        }
        
    def create(self, validated_data):
        # Ensure the role is set to 'manager'
        validated_data['role'] = 'manager'
        manager = Employee(**validated_data)
        manager.password = make_password(validated_data['password'])  # Hash the password
        manager.save()
        return manager

    def validate(self, attrs):
        # Ensure the email is unique for the manager
        if Employee.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError("Email already exists.")
        return attrs

class EmployeeSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = Employee
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'hire_date', 'role', 'manager', 'password']
        extra_kwargs = {
            'role': {'default': 'employee'} , # Ensure role is always 'employee'
            'manager': {'read_only': True} 
        }
    def create(self, validated_data):
        # Get the manager from the context (this will be provided in the view)
        manager = self.context.get('manager')
        validated_data['role'] = 'employee'
        # Create the employee, setting the manager explicitly
        employee = Employee.objects.create(**validated_data,manager=manager) # Set the manager
        employee.password = make_password(validated_data['password'])  # Hash the password
        employee.save()
        return employee
    def validate(self, attrs):
        # Ensure the email is unique for the manager
        if Employee.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError("Email already exists.")
        return attrs


from django.contrib.auth.hashers import check_password


class EmployeeLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        try:
            employee = Employee.objects.get(email=email)
        except Employee.DoesNotExist:
            raise serializers.ValidationError('Employee not found.')

        # Check if the password matches
        if not check_password(password, employee.password):
            raise serializers.ValidationError('Invalid credentials.')

        # Ensure the employee is active
        if not employee.is_active:
            raise serializers.ValidationError('Employee account is inactive.')

        # Check if the employee is a manager
        # if employee.role != 'manager':
        #     raise serializers.ValidationError('Only managers can log in here.')

        refresh = RefreshToken.for_user(employee)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'email': employee.email,
            'user_id': employee.id,
            'role': employee.role
        }





class MaintenanceRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = MaintenanceRecord
        fields = '__all__'

class AssetSerializer(serializers.ModelSerializer):
    maintenance_records = MaintenanceRecordSerializer(many=True, read_only=True) 

    class Meta:
        model = Asset
        fields = ['name', 'description', 'price', 'purchase_date', 'maintenance_records','employee','barcode']

        
class CustomTokenObtainPairSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        user = authenticate(username=attrs['username'], password=attrs['password'])
        if user is None:
            raise serializers.ValidationError('Invalid credentials')
        
        if not user.is_superuser:
            raise serializers.ValidationError('You do not have superuser access.')
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token


        return {
            'access': str(access_token),
            'refresh': str(refresh), 
        }