from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST

from django.contrib.auth.models import User, Group
from api.models import UserProfile, OneTimePassword, Country, State
import re

class CustomLoginSerializer(ModelSerializer):
	email = serializers.CharField()
	password = serializers.CharField()

	class Meta:
		model = User
		fields = ['email', 'password']

	def validate_email(self, value):

		# Check to see usersexist with this email.
		try:
			user = User.objects.get(email=value)
			return value
		except User.DoesNotExist:
			raise serializers.ValidationError( 'No user with this email ID '+str(value) )
		return value


class UserProfileSerializer(ModelSerializer):
	first_name = serializers.CharField()
	last_name = serializers.CharField()
	username = serializers.CharField()
	email = serializers.EmailField()
	password = serializers.CharField()
	# user = serializers.IntegerField()

	class Meta:
		model = UserProfile
		fields = ['first_name', 'last_name', 'username', 'email', 'password', 'user_type', 'country', 'mobile_number', 'pincode', 'street_address',
					'landmark', 'city', 'state' ]

	def validate_email(self, value):

		# Check to see if any users already exist with this email as a username.
		try:
			match = User.objects.get(email=value)
		except User.DoesNotExist:
			return value
		raise serializers.ValidationError('This email address is already in use.')

	def validate_username(self, value):

		# Check to see if any users already exist with this email as a username.
		try:
			match = User.objects.get(username=value)
		except User.DoesNotExist:
			return value
		raise serializers.ValidationError('This username is already in use.')

	def validate_mobile_number(self, value):

		if len(value) != 10:
			raise serializers.ValidationError('Invalid Mobile number')
		return value


class AccountActivationSerializer(serializers.Serializer):
	"""
	Serializer for Account Activation.
	"""
	activation_key = serializers.CharField(required=True)
	email = serializers.EmailField(required=True)

	def validate_email(self, value):
		try:
			user = User.objects.get(email=value)
			if user.is_active:
				raise serializers.ValidationError('User is already Active!.')
		except User.DoesNotExist:
			raise serializers.ValidationError('No user registered with this EmailID -"'+ value +'"' )
		return value


class ResetPasswordSerializer(serializers.Serializer):
	"""
	Serializer for password Reset.
	"""
	old_password = serializers.CharField(required=True)
	new_password = serializers.CharField(required=True)


class OTPSerializer(serializers.Serializer):
	otp = serializers.CharField(required=True)
	email = serializers.EmailField()

	def validate_otp(self, value):
		# otp validation
		return value

	def validate_email(self, value):
		try:
			user = User.objects.get(email=value)
			return value
		except User.DoesNotExist:
			raise serializers.ValidationError('No user registered with this EmailID -"'+ value +'"' )
		return value


class EmailOTPSerializer(ModelSerializer):
	"""
	Serializer for 2FA Email .
	"""
	class Meta:
		model = OneTimePassword
		fields = ['otp']


class CountrySerializer(ModelSerializer):
	"""
	Serializer for Country.
	"""
	class Meta:
		model = Country
		fields = ['id','country']


class StateSerializer(ModelSerializer):
	class Meta:
		model = State
		fields = ['state',]


class UserTypeSerializer(ModelSerializer):
	"""
	Serializer for User Groups.
	"""
	class Meta:
		model = Group
		fields = ['id','name']