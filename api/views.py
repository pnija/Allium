from django.shortcuts import render
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.generics import UpdateAPIView
from rest_framework.authentication import TokenAuthentication
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST

from django.contrib.auth.models import User
from api.models import UserProfile, OneTimePassword, UserSetting
from api.serializer import *
from api.utils import send_verification_key, send_otp
import uuid
# from random import randint


class AuthTokenView(ObtainAuthToken):
	permission_classes = [AllowAny]

	def post(self, request, *args, **kwargs):
		serializer = self.serializer_class(data=request.data, context={'request': request})
		serializer.is_valid(raise_exception=True)
		user = serializer.validated_data['user']

		# user_settings = UserSetting.objects.get_or_create(user=user)

		# if user_settings.enable_2fa:
		# 	status_2fa = authenticate_2fa(user)
		# 	return Response({})

		token, created = Token.objects.get_or_create(user=user)

		return Response({
			'token': token.key,
			'user_id': user.pk,
			# 'status' : mail_status,
			'email': user.email
			})


class EmailOneTimePassword(APIView):
	serializer_class = EmailOTPSerializer
	permission_classes = [AllowAny]
	http_method_names = ['post']

	def post(self, request, *args, **kwargs):
		serializer = self.serializer_class(data=request.data, context={'request': request})
		# import pdb; pdb.set_trace()
		if serializer.is_valid():
			otp = serializer.data.get("otp")
			try:
				otp_object = OneTimePassword.objects.get(otp=otp)
				user = otp_object.user
			except OneTimePassword.DoesNotExist:
				return Response("wrong OTP please try again!")
			token, created = Token.objects.get_or_create(user=user)
			return Response({
				'token': token.key,
				'user_id': user.pk,
				# 'status' : mail_status,
				'email': user.email
				})


class Logout(APIView):
	# queryset = User.objects.all()

	def get(self, request, format=None):
		request.user.auth_token.delete()
		return Response(status=status.HTTP_200_OK)


class UserTypeListViewSet(ModelViewSet):
	queryset = Group.objects.all()
	serializer_class = UserTypeSerializer
	permission_classes = [AllowAny]

	def list(self, request, *args, **kwargs):
		queryset = self.filter_queryset(self.get_queryset())
		if not queryset:
			return Response('No UserType found', status=HTTP_400_BAD_REQUEST)
		serializer = self.get_serializer(queryset, many=True)
		return Response(serializer.data)


class CountryListViewSet(ModelViewSet):
	queryset = Country.objects.all()
	serializer_class = CountrySerializer
	permission_classes = [AllowAny]

	def list(self, request, *args, **kwargs):
		queryset = self.filter_queryset(self.get_queryset())
		if not queryset:
			return Response('No Country found', status=HTTP_400_BAD_REQUEST)
		serializer = self.get_serializer(queryset, many=True)
		return Response(serializer.data)


class StateListViewSet(ModelViewSet):
	queryset = State.objects.all()
	serializer_class = StateSerializer
	permission_classes = [AllowAny]

	def get_queryset(self):
		country_id = self.request.GET.get('country')
		if country_id:
			self.queryset = State.objects.filter(country__id=country_id)
			return self.queryset
		return self.queryset

	# def list(self, request, *args, **kwargs):
	# 	queryset = self.filter_queryset(self.get_queryset())
	# 	if not queryset:
	# 		return Response('No rooms found', status=HTTP_400_BAD_REQUEST)
	# 	serializer = self.get_serializer(queryset, many=True)
	# 	return Response(serializer.data)


class RegisterUserProfileView(ModelViewSet):
	queryset = UserProfile.objects.all()
	serializer_class = UserProfileSerializer
	permission_classes = [AllowAny]

	def create(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)
		serializer.is_valid(raise_exception=True)

		if serializer.validated_data:
			first_name = serializer.validated_data.pop('first_name')
			last_name = serializer.validated_data.pop('last_name')
			username = serializer.validated_data.pop('username')
			email = serializer.validated_data.pop('email')
			password = serializer.validated_data.pop('password')

			try:
				user = User.objects.create_user(username=username,
							email=email,
							password=password)
			except:			
				user = User.objects.get(username=username)

			user.first_name = first_name
			user.last_name = last_name
			user.is_active = False
			user.save()

			dict_data = serializer.validated_data.copy()
			dict_data.update({'user' : user})
			
			user_profile = UserProfile.objects.create(**dict_data)
			user_profile.full_name = first_name + ' ' + last_name
			user_profile.activation_key = uuid.uuid4().hex[:6].upper()			
			user_profile.save()
			print("----------->  ",user_profile.activation_key )
			mail_status = send_verification_key(user_profile.activation_key, user_profile.user)

			return Response({'email':user.email,'status': mail_status})


class ResetPassword(UpdateAPIView):
	serializer_class = ResetPasswordSerializer
	model = User

	def get_object(self, queryset=None):
		obj = self.request.user
		return obj

	def update(self, request, *args, **kwargs):
		self.object = self.get_object()
		serializer = self.get_serializer(data=request.data)

		if serializer.is_valid():
			if not self.object.check_password(serializer.data.get("old_password")):
				return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
			self.object.set_password(serializer.data.get("new_password"))
			self.object.save()
			return Response("Success.", status=status.HTTP_200_OK)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivateAccountView(UpdateAPIView):
	serializer_class = AccountActivationSerializer
	permission_classes = [AllowAny]
	model = User

	def update(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)
		if serializer.is_valid():
			key = serializer.data.get("activation_key")
			email = serializer.data.get("email")
			try:
				user = User.objects.get(email=email)
				user_profile = UserProfile.objects.get(user=user)
			except UserProfile.DoesNotExist:
				return Response("Could'nt find UserProfile object")
			
			if user_profile.activation_key == key:
				user.is_active = True
				user.save()			
				return Response("Account Activated Succesfully.", status=status.HTTP_200_OK)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)