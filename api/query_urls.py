from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('usertypes', UserTypeListViewSet, base_name='usertype-list')
router.register('country-list', CountryListViewSet, base_name='country-list')
router.register('states', StateListViewSet, base_name='states')
# router.register('profile', UpdateProfileView, base_name='user-profile')

urlpatterns = [
    url(r'^', include(router.urls)),
]