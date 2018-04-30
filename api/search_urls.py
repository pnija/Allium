from django.conf.urls import url, include
from .views import *
from rest_framework import routers

router = routers.DefaultRouter()

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^users/(?P<search>[\w\+]+)$', UserListView.as_view(), name='search-users')
]