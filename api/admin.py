from django.contrib import admin
from api.models import *

# Register your models here.
admin.site.register(Country)
admin.site.register(State)
admin.site.register(UserProfile)
admin.site.register(UserSetting)
admin.site.register(GoogleAuthenticator)