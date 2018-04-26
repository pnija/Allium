from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('sign-up', RegisterUserProfileView, base_name='register-profile')
# router.register(r'enable_2fa/(?P<2fa_method>[\w\+]+)', Enable2faViewSet, base_name='enable-2fa')
# router.register('login', AuthTokenView, base_name='token-authentication')
# router.register('get-country-list', CountryListViewSet, base_name='country-list')
# router.register('get-states', StateListViewSet, base_name='states')
# url(r'^login/', AuthTokenView.as_view(), name='authentication'),

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^login/', AuthTokenView.as_view(), name='authentication'),
    # url(r'^email-otp/', EmailOneTimePassword.as_view(), name='verify-otp'),
    url(r'^logout/', Logout.as_view(), name='logout-view'),
    url(r'^enable-2fa/(?P<auth_method>[\w\+]+)$', Enable2faView.as_view(), name='enable-2fa'),
    url(r'^authentication-2fa/', Authenticate2faView.as_view(), name='auth-2fa'),
    url(r'^reset-password/', ResetPassword.as_view(), name='reset-password'),
    url(r'^activate-account/', ActivateAccountView.as_view(), name='activate-account'),
    # url(r'^enable-google_auth/', EnableGoogleAuthView.as_view(), name='enable-google_auth'),
    url(r'^disable-google_auth/', DisableGoogleAuthView.as_view(), name='disable-google_auth'),
]