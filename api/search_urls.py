from django.conf.urls import url, include
from .views import SearchListView
from rest_framework import routers

router = routers.DefaultRouter()

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^users/(?P<profile_id>[\w\+]+)/(?P<field_name>[\w\+]+)$', SearchListView.as_view(), name='search-user-info')
]