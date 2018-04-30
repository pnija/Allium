from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()
router.register('profile', UpdateProfileView, base_name='user-profile')

urlpatterns = [
    url(r'^', include(router.urls)),
]