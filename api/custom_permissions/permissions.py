from rest_framework import permissions
from django.contrib.auth.models import Group


class PartnerAccessPermission(permissions.BasePermission):
	message = "Only 'Partner' allowed to access this api."
	
	def is_member(self, user):
		return user.groups.filter(name='Partner').exists()

	def has_permission(self, request, view):
		"""
		Return `True` if permission is granted, `False` otherwise.
		"""	
		if not request.user.is_anonymous:
			if self.is_member(request.user):
				return True
		return False

	def has_object_permission(self, request, view, obj):
		"""
		Return `True` if permission is granted, `False` otherwise.
		"""
		if not request.user.is_anonymous:
			if self.is_member(request.user):
				return True
		return False


class AdminAccessPermission(permissions.BasePermission):
	message = "Only 'Admin' allowed to access this api."
	
	def is_admin(self, user): 
		return user.groups.filter(name='Admin').exists()

	def has_permission(self, request, view):
		"""
		Return `True` if permission is granted, `False` otherwise.
		"""		
		if not request.user.is_anonymous:
			
			if request.user.is_superuser:
				return True
			else:
				if self.is_admin(request.user):
					return True
		return False

	def has_object_permission(self, request, view, obj):
		"""
		Return `True` if permission is granted, `False` otherwise.
		"""
		if not request.user.is_anonymous:
			
			if request.user.is_superuser:
				return True
			else:
				if self.is_admin(request.user):
					return True
		return False