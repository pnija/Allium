from django.conf.urls import url, include
from .views import *
from rest_framework import routers
from api.views import AuthTokenView, Logout, EmailOneTimePassword, ActivateAccountView, ResetPassword

router = routers.DefaultRouter()
router.register('sign-up', RegisterUserProfileView, base_name='register-profile')

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^token-auth/', AuthTokenView.as_view(), name='authentication'),
    url(r'^email-otp/', EmailOneTimePassword.as_view(), name='verify-otp'),
    url(r'^logout/', Logout.as_view(), name='logout-view'),
    url(r'^reset-password/', ResetPassword.as_view(), name='reset-password'),
    url(r'^activate-account/', ActivateAccountView.as_view(), name='activate-account'),
    # url(r'^sign-up/', RegisterUserProfileView.as_view(), name='register-profile'),
]