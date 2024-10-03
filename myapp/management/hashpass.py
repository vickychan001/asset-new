from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password

class Command(BaseCommand):
    help = 'Rehash passwords for all users'

    def handle(self, *args, **kwargs):
        for user in User.objects.all():
            if not user.password.startswith(('pbkdf2_sha256$', 'argon2$', 'bcrypt$', 'crypt$')):
                user.password = make_password(user.password)
                user.save()
                self.stdout.write(self.style.SUCCESS(f'Updated password for user: {user.username}'))
            else:
                self.stdout.write(self.style.SUCCESS(f'User: {user.username} already has a hashed password'))
