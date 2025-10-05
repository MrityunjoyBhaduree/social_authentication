from django.contrib import admin
from social.models import User, UserType


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email_or_phone', 'is_active', 'full_name',
                    'user_type']

    search_fields = ['email_or_phone', 'full_name']
    list_filter = ['user_type']
    list_editable = ['is_active', 'user_type']
    search_help_text = ['Search by email or phone or full_name']


@admin.register(UserType)
class UserTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'status']
    list_editable = ['status']

