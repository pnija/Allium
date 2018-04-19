from django.db import models
from django.contrib.auth.models import User, Group
# Create your models here.

GOOGLE_AUTH = 'GA'
EMAIL_OTP = 'EO'
SMS_OTP =  'SO'

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
	user_type = models.ForeignKey(Group, on_delete=models.CASCADE)
	country = models.ForeignKey(Country, on_delete=models.CASCADE)
	full_name = models.CharField(max_length=100)
	mobile_number = models.CharField(max_length=10, null=False)
	pincode = models.IntegerField(null=False)
	street_address = models.CharField(max_length=300, null=False)
	landmark = models.CharField(max_length=100, null=False)
	city = models.CharField(max_length=50)
	state = models.ForeignKey(State, on_delete=models.CASCADE)
	activation_key = models.CharField(max_length=50)

	def __str__(self):
		return ("{}").format(self.full_name)

class UserSetting(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	enable_2fa = models.BooleanField(default=False)
	method_2fa = models.CharField(max_length=10, choices=METHODS_2FA, default=EMAIL_OTP)

	