from django.conf import settings
from django.core.mail import EmailMessage
from django.core.mail import send_mail
from api.models import *
from api.models import GOOGLE_AUTH, EMAIL_OTP, SMS_OTP
import uuid


def send_verification_key(key, user):
	body = "Your verification code is: "+str(key)
	subject = 'Allium Account Verification'
	email = EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, (user.email,))
	email.content_subtype = 'html'

	# send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email,])
	try:
		email.send()
	except Exception as e:
		print(e.strerror)
		return  str(e.strerror)
	return 'Account Activation code sent to your email address - '+ str(user.email) +'. Thank you'


def send_otp(otp_object, user):
	body = 'Your One Time Password is '+str(otp_object.otp)
	subject = 'Allium One Time Password(OTP)'
	email = EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, (user.email,))
	email.content_subtype = 'html'

	try:
		email.send()
	except Exception as e:
		print(e.strerror)
		return  str(e.strerror)
	return 'Your One Time Password(otp) send to your email ID : '+str(user.email)


def authenticate_2fa(user):
	user_setting = UserSetting.objects.get(user=user)
	print("Method : ", user_setting.method_2fa)
	if user_setting.method_2fa == GOOGLE_AUTH :
		return "Authenticate with Google Authenticator"
	
	elif user_setting.method_2fa == SMS_OTP:
		print('SMS OTP')
	
	elif user_setting.method_2fa == EMAIL_OTP:
		print ('Email OTP')
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

		return mail_status
	else:
		return "Invalid 2fa setting"


def send_password_verification_key(user):
	key = uuid.uuid4().hex[:6].upper()
	pswd_reset_obj, created = PasswordResetVerification.objects.get_or_create(user=user)
	pswd_reset_obj.verification_key = key
	pswd_reset_obj.save()

	body = 'Your Password verification Key is : '+str(key)
	subject = 'Password Verification key'
	email = EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, (user.email,))
	email.content_subtype = 'html'

	try:
		email.send()
	except Exception as e:
		print(e.strerror)
		return  str(e.strerror)
	return "Password Verification Key to change-password is sent to your mailID "+str(user.email)





# def enable_efa(method_2fa):
# 	user_setting = UserSetting.objects.get(user=user)
	
# 	user_setting, created = UserSetting.objects.get_or_create(user = request.user)
# 	user_setting.enable_2fa = True
	
# 	if method_2fa == GOOGLE_AUTH:		
# 		user_setting.method_2fa = GOOGLE_AUTH
# 		user_setting.save()

# 		try:
# 			google_auth_object = GoogleAuthenticator.objects.get(user=request.user)
# 		except GoogleAuthenticator.DoesNotExist:
# 			google_auth_object = None
		
# 		if not google_auth_object:
# 			google_2fa_key = pyotp.random_base32()
# 			google_auth_object = GoogleAuthenticator.objects.create(
# 				user= request.user,
# 				google_2fa_key=google_2fa_key)

# 	elif method_2fa == SMS_OTP:
# 		print('SMS OTP')
	
# 	else :
# 		print ('Email OTP')
# 		otp = uuid.uuid4().hex[:6].upper()

# 		while True:
# 			if OneTimePassword.objects.filter(email = cleaned_info['username']).exists():
# 				otp = uuid.uuid4().hex[:6].upper()
# 			else:
# 				break

# 		otp_object, created = OneTimePassword.objects.get_or_create(user=user)
# 		otp_object.otp = otp
# 		print(" ---------->  ", otp)
# 		mail_status = send_otp(otp_object, user)

# 		return mail_status