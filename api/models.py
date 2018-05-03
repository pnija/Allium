from django.db import models
from django.contrib.auth.models import User, Group
# Create your models here.

GOOGLE_AUTH = 'google_auth'
EMAIL_OTP = 'email_otp'
SMS_OTP =  'sms_otp'

METHODS_2FA = (
	(GOOGLE_AUTH,'Google Auth'),
	(EMAIL_OTP,'Email OTP'),
	(SMS_OTP,'SMS OTP'))


class Country(models.Model):
	country = models.CharField(max_length=30)

	def __str__(self):
		return ("{}").format(self.country)


class State(models.Model):
	country = models.ForeignKey(Country, on_delete=models.CASCADE)
	state = models.CharField(max_length=50)

	def __str__(self):
		return ("{}").format(self.state)


class OneTimePassword(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	otp = models.CharField(null=False, unique=True, max_length=10)

	def __str__(self):
		return ("{}, {}").format(self.otp, self.user)


class UserProfile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	user_type = models.ForeignKey(Group, on_delete=models.CASCADE, null=True)
	country = models.ForeignKey(Country, on_delete=models.CASCADE, null=True)
	full_name = models.CharField(max_length=100, null=True)
	mobile_number = models.CharField(max_length=10, null=True)
	pincode = models.IntegerField(null=True)
	street_address = models.CharField(max_length=300, null=True)
	landmark = models.CharField(max_length=100, null=True)
	city = models.CharField(max_length=50, null=True)
	state = models.ForeignKey(State, on_delete=models.CASCADE, null=True)
	activation_key = models.CharField(max_length=50, null=True)

	def __str__(self):
		return ("{}").format(self.user.username)


class UserSetting(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	enable_2fa = models.BooleanField(default=False)
	method_2fa = models.CharField(max_length=20, choices=METHODS_2FA, default=EMAIL_OTP)

	def __str__(self):
		return ("{}, {}, {}").format(self.user, self.method_2fa, self.enable_2fa)


class GoogleAuthenticator(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	google_2fa_key = models.CharField(max_length=50)

	def __str__(self):
		return ("{}, {}").format(self.user, self.google_2fa_key)


class PasswordResetVerification(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	verification_key = models.CharField(max_length=50)
	created_at = models.DateTimeField(auto_now_add=True, blank=True)

	def __str__(self):
		return ("{}, {}").format(self.user, self.verification_key)