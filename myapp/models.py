from django.db import models
from django.contrib.auth.hashers import make_password

class Employee(models.Model):
    ROLE_CHOICES = (
        ('manager', 'Manager'),
        ('employee', 'Employee'),
    )

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    hire_date = models.DateField()
    is_active = models.BooleanField(default=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='employee')
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='employees')
    password = models.CharField(max_length=128)  # Password field
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"

class Asset(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    purchase_date = models.DateField()
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='assets')
    barcode = models.CharField(max_length=100, unique=True)  # Barcode for tracking

    def __str__(self):
        return self.name

class MaintenanceRecord(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='maintenance_records')
    maintenance_date = models.DateField()
    description = models.TextField()
    performed_by = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='maintenance_records')

    def __str__(self):
        return f"{self.asset.name} - {self.maintenance_date}"
