from django.shortcuts import render
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ViewSet
from rest_framework.generics import UpdateAPIView, GenericAPIView
from rest_framework.authentication import TokenAuthentication
from rest_framework import status, generics
# from django_filters import rest_framework as filters
from rest_framework import filters

from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Q
from api.models import UserProfile, OneTimePassword, UserSetting, GoogleAuthenticator
from api.models import GOOGLE_AUTH, EMAIL_OTP, SMS_OTP
from api.serializer import *
from api.utils import send_verification_key, send_otp, authenticate_2fa
import uuid
import pyotp

class AuthTokenView(ObtainAuthToken):
	permission_classes = [AllowAny]

	def post(self, request, *args, **kwargs):
		serializer = self.serializer_class(data=request.data, context={'request': request})
		serializer.is_valid(raise_exception=True)
		user = serializer.validated_data['user']
		user_settings, created = UserSetting.objects.get_or_create(user=user)
		
		if user_settings.enable_2fa:
			status_2fa = authenticate_2fa(user)
			return Response({
				'status' : 'success',
				'message' : status_2fa
				})
		else:
			token, created = Token.objects.get_or_create(user=user)
			return Response({
				'token': token.key,
				'user_id': user.pk,
				# 'status' : mail_status,
				'email': user.email
				})


class Logout(APIView):
	queryset = User.objects.all()

	def get(self, request, format=None):
		request.user.auth_token.delete()
		return Response('Logout',status=status.HTTP_200_OK)


class Enable2faView(GenericAPIView):
	http_method_names = ['get']

	def get(self, request, *args, **kwargs):
		user = request.user
		method_2fa = self.kwargs.get('auth_method', '')

		user_setting, created = UserSetting.objects.get_or_create(user = request.user)
		user_setting.enable_2fa = True

		if method_2fa == GOOGLE_AUTH:
			user_setting.method_2fa = GOOGLE_AUTH
			user_setting.save()

			try:
				google_auth_object = GoogleAuthenticator.objects.get(user=request.user)
			except GoogleAuthenticator.DoesNotExist:
				google_auth_object = None
			
			if not google_auth_object:
				google_2fa_key = pyotp.random_base32()
				google_auth_object = GoogleAuthenticator.objects.create(
					user= request.user,
					google_2fa_key=google_2fa_key)
				return Response({
					'status' : 'success',
					'message' : 'Created new google verification key',
					'Verification_key' : google_auth_object.google_2fa_key,
					})
			else:
				return Response({
					'status' : 'success',
					'message' : 'You have existing verification key',
					'Verification_key' : google_auth_object.google_2fa_key,
					})

		elif method_2fa == EMAIL_OTP:
			user_setting.method_2fa = EMAIL_OTP
			user_setting.save()

			otp = uuid.uuid4().hex[:6].upper()

			while True:
				if OneTimePassword.objects.filter(otp = otp).exists():
					otp = uuid.uuid4().hex[:6].upper()
				else:
					break

			otp_object, created = OneTimePassword.objects.get_or_create(user=user)
			otp_object.otp = otp
			otp_object.save()
			print(" ---------->  ", otp)
			mail_status = send_otp(otp_object, user)
			
			return Response({
				'status' : 'success',
				'message' : mail_status
				})

		elif method_2fa == SMS_OTP:
			return Response({
				'status' : 'success',
				'message' : 'Mobile SMS not available now'
				})
		else:
			return Response({
				'status' : 'failed',
				'message' : 'Invalid input.'
				})


class Disable2faView(GenericAPIView):
	http_method_names = ['get']
	def get(self, request):
		user = request.user
		try:
			user_setting = UserSetting.objects.get(user = request.user)
			user_setting.delete()
		except UserSetting.DoesNotExist:
			user_setting = None
		
		if not (user_setting is None):
			return Response({
				'status' : 'failed',
				'message' : 'User not yet enabled Google Athentication !'
				})
		else:
			return Response({
				'status' : 'success',
				'message' : 'Disabled 2FA.'
				})


class Authenticate2faView(GenericAPIView):
	serializer_class = OTPSerializer
	permission_classes = [AllowAny]
	http_method_names = ['post']

	def post(self, request, format=None):		
		serializer = self.serializer_class(data=request.data, context={'request': request})
		serializer.is_valid(raise_exception=True)
		
		if serializer.validated_data:
			email = request.data.get('email')
			otp_code = request.data.get('otp')
			user = User.objects.get(email=email)
			user_setting = UserSetting.objects.get(user=user)

			if user_setting.method_2fa == GOOGLE_AUTH:
				try:
					user_auth_object = GoogleAuthenticator.objects.get(user=user)				
				except GoogleAuthenticator.DoesNotExist:
					return Response({
						'status' : 'failed',
						'message' : 'Please enable Google Authenticator',
						})

				google_2fa_key = user_auth_object.google_2fa_key
				totp = pyotp.TOTP(google_2fa_key)

				if totp.verify(otp_code):
					token, created = Token.objects.get_or_create(user=user)
					return Response({
						'status' : 'success',
						'message' : 'Succesfully authenticated with Google Authenticator',
						'token': token.key,
						})
				return Response({
					'status' : 'failed',
					'message' : 'Wrong OTP',
					})

			elif user_setting.method_2fa == EMAIL_OTP:
				
				try:
					otp_object = OneTimePassword.objects.get(otp=otp_code, user=user)
				except OneTimePassword.DoesNotExist:
					return Response({
						'status' : 'failed',
						'message' : 'wrong OTP please try again!'
						})
				
				token, created = Token.objects.get_or_create(user=user)
				return Response({
					'status' : 'success',
					'token': token.key,
					'user_id': user.pk,
					})
			else:
				pass

		return Response({
			'status' : 'failed',
			})


class UserProfileView(ModelViewSet):
	queryset = UserProfile.objects.all()
	serializer_class = UserProfileSerializer
	http_method_names = ['get', 'patch']

	def get_object(self):
		obj = User.objects.get(user=self.rquest.user)
		return obj

	def update(self, request, *args, **kwargs):
		self.object = self.get_object()
		serializer = self.get_serializer(data=request.data)

		if serializer.is_valid():
			return Response("Success.update")


class UserTypeListViewSet(ModelViewSet):
	queryset = Group.objects.all()
	serializer_class = UserTypeSerializer
	permission_classes = [AllowAny]
	http_method_names = ['get']

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
	http_method_names = ['get']

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
	http_method_names = ['get']

	def get_queryset(self):
		country_id = self.request.GET.get('country')
		if country_id:
			self.queryset = State.objects.filter(country__id=country_id)
			return self.queryset
		return self.queryset


class RegisterUserProfileView(ModelViewSet):
	queryset = UserProfile.objects.all()
	serializer_class = UserProfileSerializer
	permission_classes = [AllowAny]
	http_method_names = ['post']

	def create(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)
		serializer.is_valid(raise_exception=True)

		if serializer.validated_data:
			first_name = serializer.validated_data.pop('first_name', '')
			last_name = serializer.validated_data.pop('last_name', '')
			username = serializer.validated_data.pop('username')
			email = serializer.validated_data.pop('email')
			password = serializer.validated_data.pop('password')
			
			user = User.objects.create_user(username=username,
						email=email,
						password=password)

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
	http_method_names = ['put']
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
	http_method_names = ['put']

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


class UpdateProfileView(ModelViewSet):
	queryset = UserProfile.objects.all()
	serializer_class = ProfileSerializer
	http_method_names = ['get', 'patch']

	def get_queryset(self):
		return UserProfile.objects.filter(user=self.request.user)

	def update(self, request, *args, **kwargs):
		user = self.request.user
		instance = UserProfile.objects.get(user=user)
		serializer = ProfileSerializer(instance, data=request.data, partial=True)
		if serializer.is_valid():
			serializer.save()
			serializer = self.get_serializer(userlist, many=True)
			return Response(serializer.data)
		return Response('Invalid Data.')


class UserListView(GenericAPIView):
	http_method_names = ['get']
	serializer_class = ProfileSerializer

	def get(self, request, *args, **kwargs):
		user = request.user
		if user.groups.filter(name=group_name).exists():
			search_val = self.kwargs.get('search', '')
			q1 = Q(user__first_name=search_val)
			q2 = Q(user__last_name=search_val)
			q3 = Q(user__email=search_val)
			q4 = Q(mobile_number=search_val)

			try:
				value = int(search_val)
				q5 = Q(pincode=value)
			except ValueError:
				q5 = Q(pincode=0)

			q6 = Q(street_address=search_val)
			q7 = Q(landmark=search_val)
			q8 = Q(city=search_val)
			query = q1|q2|q3|q4|q5|q6|q7|q8
			userlist = UserProfile.objects.filter(query)
			serializer = self.get_serializer(userlist, many=True)
			return Response(serializer.data)
		else:
			return Response({
				'You have no permissions to view user details'
				})