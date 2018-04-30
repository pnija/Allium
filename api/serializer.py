from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST

from django.contrib.auth.models import User, Group
from api.models import UserProfile, OneTimePassword, Country, State
import re


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
	first_name = serializers.CharField(required=False)
	last_name = serializers.CharField(required=False)
	username = serializers.CharField()
	email = serializers.EmailField()
	password = serializers.CharField()
	user_type = serializers.CharField(source='user_type.name',required=False)


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

	# def validate_mobile_number(self, value):

	# 	if len(value) != 10:
	# 		raise serializers.ValidationError('Invalid Mobile number')
	# 	return value


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
	user_id = serializers.IntegerField(required=True)

	def validate_otp(self, value):
		# otp validation
		return value

	def validate_user_id(self, value):
		try:
			user = User.objects.get(pk=value)
			return value
		except User.DoesNotExist:
			raise serializers.ValidationError('No user exist with this ID -"'+ value +'"' )
		return value


class EmailOTPSerializer(ModelSerializer):
	"""
	Serializer for 2FA Email .
	"""
	class Meta:
		model = OneTimePassword
		fields = ['otp']




class UserSerializer(serializers.ModelSerializer):
	first_name = serializers.CharField()
	last_name = serializers.CharField()
	email = serializers.EmailField(required=True,)
	username = serializers.CharField()
	password = serializers.CharField(min_length=8,allow_null=True ,required=False)

	class Meta:
		model = User
		fields = ('first_name', 'last_name', 'username', 'email', 'password')


class ProfileSerializer(ModelSerializer):
	
	user = UserSerializer()

	class Meta:
		model = UserProfile
		fields = ['id', 'user', 'user_type', 'country', 'mobile_number', 'pincode', 'street_address',
			'landmark', 'city', 'state' ]
		depth = 1

	def update(self, instance, validated_data):
		user_data = validated_data.pop('user')
		user = instance.user
		user.first_name = user_data.get('first_name', user.first_name)
		user.last_name = user_data.get('last_name', user.first_name)
		user.email = user_data.get('email', user.email)
		user.username = user_data.get('email', user.username)
		user.save()
		return instance
		
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