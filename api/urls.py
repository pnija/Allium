from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('sign-up', RegisterUserProfileView, base_name='register-profile')
router.register('delete', DeleteUserProfile, base_name='delete-profile')

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^login/', AuthTokenView.as_view(), name='authentication'),
    url(r'^logout/', Logout.as_view(), name='logout-view'),
    url(r'^enable-2fa/(?P<auth_method>[\w\+]+)$', Enable2faView.as_view(), name='enable-2fa'),
    url(r'^disable-2fa/', Disable2faView.as_view(), name='disable-2fa'),
    url(r'^authentication-2fa/', Authenticate2faView.as_view(), name='auth-2fa'),
    url(r'^change-password/', ChangePassword.as_view(), name='change-password'),
    url(r'^forgot-password/', ForgotPassword.as_view(), name='forgot-password'),
    url(r'^reset-password/', ResetPassword.as_view(), name='reset-password'),
    url(r'^activate-account/', ActivateAccountView.as_view(), name='activate-account'),    
    # url(r'^users/(?P<search>[\w\+]+)$', UserListView.as_view(), name='search-users'),
]