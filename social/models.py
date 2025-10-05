from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.timestampModel import TimestampModel
from social.utils import check_email


class UserType(models.Model):
    """
    Create model for user type
    """
    USER_TYPE = (
        ('General', 'General'),
        ('Admin', 'Admin')
    )
    name = models.CharField(max_length=255, choices=USER_TYPE)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class CustomUserManager(BaseUserManager):
    def _create_user(self, password, user_type, full_name=None,
                     email=None, phone=None, gender=None, **extra_fields):
        """
        Base method for creating users
        """
        if email is None and phone is None:
            raise ValueError('Either email or phone must be provided')

        if email:
            email = self.normalize_email(email)
            extra_fields.setdefault('email_or_phone', email)
        if phone:
            extra_fields.setdefault('email_or_phone', phone)

        extra_fields.setdefault('is_active', True)

        if user_type == 'Admin':
            if email:
                user = self.model(
                    email=email,
                    **extra_fields
                )
            if phone:
                user = self.model(
                    phone=phone,
                    **extra_fields
                )

        else:
            if email:
                user = self.model(
                    email=email,
                    full_name=full_name,

                    **extra_fields
                )
            if phone:
                user = self.model(
                    phone=phone,
                    full_name=full_name,
                    **extra_fields
                )
        if gender:
            user.gender = gender

        user.set_password(password)
        user_type_obj, created = UserType.objects.get_or_create(name=user_type)
        user.user_type = user_type_obj
        user.save(using=self._db)
        return user

    def create_user(self, email=None, phone=None, password=None,
                    full_name=None, gender=None, **extra_fields):
        """
        Create and save a general user
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        user_type = "General"
        if email is not None:
            return self._create_user(email=email, password=password,
                                     full_name=full_name,
                                     user_type=user_type,
                                     gender=gender,
                                     **extra_fields)
        if phone is not None:
            return self._create_user(phone=phone, password=password,
                                     full_name=full_name,
                                     user_type=user_type,
                                     gender=gender,
                                     **extra_fields)

    def create_superuser(self, email_or_phone=None, password=None,
                         **extra_fields):
        """
        Create and save a superuser
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        user_type = "Admin"
        is_email = check_email(email_or_phone)
        if is_email:
            return self._create_user(email=email_or_phone, password=password,
                                     user_type=user_type, full_name='Admin',
                                     **extra_fields)
        else:

            return self._create_user(phone=email_or_phone, password=password,
                                     user_type=user_type, full_name='Admin',
                                     **extra_fields)

class User(AbstractBaseUser, PermissionsMixin, TimestampModel):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    ]

    email = models.EmailField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    email_or_phone = models.CharField(max_length=100, unique=True,
                                      db_index=True)
    user_type = models.ForeignKey(UserType, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=50, blank=True)
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES,
                              blank=True)
    image = models.ImageField(upload_to='profile_image/', blank=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email_or_phone'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email_or_phone

    def get_token_for_user(self):
        refresh_token = RefreshToken.for_user(self)

        tokens = {
            'refresh_token': str(refresh_token),
            'access_token': str(refresh_token.access_token)
        }
        return tokens
