from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('sign-up', RegisterUserProfileView, base_name='register-profile')
# router.register('get-usertypes', UserTypeListViewSet, base_name='usertype-list')
# router.register('get-country-list', CountryListViewSet, base_name='country-list')
# router.register('get-states', StateListViewSet, base_name='states')

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^login/', AuthTokenView.as_view(), name='authentication'),
    # url(r'^email-otp/', EmailOneTimePassword.as_view(), name='verify-otp'),
    url(r'^logout/', Logout.as_view(), name='logout-view'),
    url(r'^reset-password/', ResetPassword.as_view(), name='reset-password'),
    url(r'^activate-account/', ActivateAccountView.as_view(), name='activate-account'),
]