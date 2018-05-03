from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('', UpdateProfileView, base_name='user-profile')
router.register('user_type', UpdateUserTypeView, base_name='user-type')

urlpatterns = [
    url(r'^', include(router.urls)),
]