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
	id = serializers.IntegerField()

	class Meta:
		model = Country
		fields = ['id','country']


class StateSerializer(ModelSerializer):
	id = serializers.IntegerField()
	class Meta:
		model = State
		fields = ['id', 'state']


class UserTypeSerializer(ModelSerializer):
	"""
	Serializer for User Groups.
	"""
	name = serializers.CharField()
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
		extra_kwargs = {'password': {'write_only': True}}
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
	password = serializers.CharField(min_length=8,allow_null=True ,required=False, write_only=True)

	class Meta:
		model = User
		fields = ('first_name', 'last_name', 'username', 'email', 'password')


class ProfileSerializer(ModelSerializer):
	
	user = UserSerializer()
	user_type = UserTypeSerializer()
	country = CountrySerializer()
	state = StateSerializer()

	class Meta:
		model = UserProfile
		fields = ['id', 'user', 'user_type', 'country', 'mobile_number', 'pincode', 'street_address',
			'landmark', 'city', 'state' ]
		depth = 1

	def update(self, instance, validated_data):
		user_data = validated_data.pop('user')
		user = instance.user

		# Country
		country_data  = validated_data.pop('country')
		country_id = country_data.get('id', '')
		
		try:
			country = Country.objects.get(id=country_id)
			instance.country = country
		except:
			pass

		# State
		state_data  = validated_data.pop('state')
		state_id = state_data.get('id', '')
		
		try:
			state = State.objects.get(id=state_id)
			instance.state = state
		except:
			pass

		# User:
		user.first_name = user_data.get('first_name', user.first_name)
		user.last_name = user_data.get('last_name', user.first_name)
		user.email = user_data.get('email', user.email)
		user.username = user_data.get('email', user.username)
		user.save()
		# UserProfile
		instance.mobile_number = validated_data.get('mobile_number', instance.mobile_number)
		instance.pincode = validated_data.get('pincode', instance.pincode)
		instance.street_address = validated_data.get('street_address', instance.street_address)
		instance.landmark = validated_data.get('landmark', instance.landmark)
		instance.city = validated_data.get('city', instance.city)
		instance.save()
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


class UpdateUserTypeSerializer(ModelSerializer):
	
	user_type = UserTypeSerializer()

	class Meta:
		model = UserProfile
		fields = ['id', 'user_type' ]
		depth = 1

	def update(self, instance, validated_data):
		user = instance.user
		user_type_data  = validated_data.pop('user_type')
		user_type_name = user_type_data.get('name', '')
		
		try:
			group = Group.objects.get(name=user_type_name)
			instance.user_type = group
			instance.save()
			user.groups.add(group)
		except Group.DoesNotExist:
			return serializers.ValidationError('Invalid User Type')		
		return instance