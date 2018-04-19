from rest_framework.serializers import ModelSerializer
from rest_framework import serializers

from django.contrib.auth.models import User
from api.models import UserProfile, OneTimePassword


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


class EmailOTPSerializer(ModelSerializer):
	"""
	Serializer for 2FA Email .
	"""
	class Meta:
		model = OneTimePassword
		fields = ['otp']