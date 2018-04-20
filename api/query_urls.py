from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('get-usertypes', UserTypeListViewSet, base_name='usertype-list')
router.register('get-country-list', CountryListViewSet, base_name='country-list')
router.register('get-states', StateListViewSet, base_name='states')

urlpatterns = [
    url(r'^', include(router.urls)),
]