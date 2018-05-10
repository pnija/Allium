from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User, Group


class Command(BaseCommand):
    def handle(self, *args, **options):
        
        if User.objects.count() == 0:            
            user = User.objects.create_superuser(username='allium', email='alliumdummy@mail.in', password='admin@123')            
            if user:
                print("Created Super-Admin username : 'allium', password : 'admin@123' ")

        # Create User Groups
        customer, created_c = Group.objects.get_or_create(name='Customer')
        partner, created_p = Group.objects.get_or_create(name='Partner')
        admin, created_a = Group.objects.get_or_create(name='Admin')
        if customer and partner and admin:
            print("Created User Types 'Customer' 'Partner' 'Admin' ")