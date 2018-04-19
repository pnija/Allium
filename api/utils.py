from django.conf import settings
from django.core.mail import EmailMessage
from api.models import UserSetting
from api.models import GOOGLE_AUTH, EMAIL_OTP, SMS_OTP
import uuid

def send_verification_key(key, user):
	email = EmailMessage('Activate Your Account', "Your verification code is: "+str(key), settings.DEFAULT_FROM_EMAIL, (user.email,))
	email.content_subtype = 'html'
	try:
		email.send()
	except Exception as e:
		print(e.strerror)
		return  str(e.strerror)
	return 'Account Activation code sent to your email address - '+ str(user.email) +'. Thnk you'


def send_otp(otp_object, user):
	email = EmailMessage('Your One Time Password is '+str(otp_object.otp), settings.DEFAULT_FROM_EMAIL, (user.email,))
	email.content_subtype = 'html'
	try:
		email.send()
	except Exception as e:
		print(e.strerror)
		return  str(e.strerror)
	return 'Your One Time Password(otp) send to your email'


def authenticate_2fa(user):
	user_setting = UserSetting.objects.get(user=user)
	
	if user_setting.method_2fa == GOOGLE_AUTH :
		print('Google Auth')
	
	elif user_setting.method_2fa == SMS_OTP:
		print('SMS OTP')
	
	else :
		print ('Email OTP')
		otp = uuid.uuid4().hex[:6].upper()

		while True:
			if OneTimePassword.objects.filter(email = cleaned_info['username']).exist():
				otp = uuid.uuid4().hex[:6].upper()
			else:
				break

		otp_object, created = OneTimePassword.objects.get_or_create(user=user)
		otp_object.otp = otp
		print(" ---------->  ", otp)
		mail_status = send_otp(otp_object, user)

		return mail_status