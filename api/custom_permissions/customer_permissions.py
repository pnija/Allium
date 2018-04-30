from rest_framework import permissions
from django.contrib.auth.models import Group

class CustomerAccessPermission(permissions.BasePermission):
	message = 'Adding customers allowed.'
	
	def is_member(self, user):
		return user.groups.filter(name='Customer').exists()

	def has_permission(self, request, view):
		"""
		Return `True` if permission is granted, `False` otherwise.
		"""

		print("Custom :- has_permission")		
		if not request.user.is_anonymous:
			if self.is_member(request.user):
				return True
			else:
				print("User not a member in Group 'Customer' ")
		else:
			print("Anonymous User")

		return False

	def has_object_permission(self, request, view, obj):
		"""
		Return `True` if permission is granted, `False` otherwise.
		"""
		print("Custom :- has_object_permission")
		if not request.user.is_anonymous:
			if self.is_member(request.user):
				return True
			else:
				print("User not a member in Group 'Customer' ")
		else:
			print("Anonymous User")
		return False