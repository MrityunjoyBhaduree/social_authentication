import logging
import re
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers

from authentication.utils import CustomSerializerValidationError
from social.models import User
from social.utils import (
    check_email,
    check_phone_number,
    get_phone_number,
)

logger = logging.getLogger(__name__)
PASSWORD_REGEX = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d\W_]{8,}$"


class UserRegisterSerializer(serializers.Serializer):
    """
    Custom serializer for creating user with either email or phone.
    """
    password = serializers.CharField(required=True, write_only=True)
    email = serializers.CharField(required=False, write_only=True)
    phone = serializers.CharField(required=False, write_only=True)
    full_name = serializers.CharField(required=True, write_only=True)
    gender = serializers.CharField(required=False, write_only=True)
    token = serializers.SerializerMethodField()

    def validate(self, attrs):
        email = attrs.get("email", None)
        phone = attrs.get("phone", None)
        password = attrs.get("password", None)

        # Check if at least one of email or phone is provided
        if not email and not phone:
            raise CustomSerializerValidationError(
                "Either email or phone number must be provided.",
                status_code=400
            )

        if len(password) < 8:
            raise CustomSerializerValidationError(
                "Password length should be at least 8 characters.",
                status_code=400
            )
        if not re.fullmatch(PASSWORD_REGEX, password):
            raise CustomSerializerValidationError(
                "Password must contain at least 8 alphanumeric "
                "characters.",
                status_code=400
            )

        if email:
            is_email = check_email(email)
            if not is_email:
                raise CustomSerializerValidationError(
                    "Invalid email format.", status_code=400
                )

            email_qs = User.objects.filter(email_or_phone=email)
            if email_qs.exists():
                raise CustomSerializerValidationError(
                    "Email already exists.", status_code=400
                )
            attrs["email"] = email

        if phone:
            formatted_phone = get_phone_number(phone)
            is_phone = check_phone_number(formatted_phone)
            if not is_phone:
                raise CustomSerializerValidationError(
                    "Invalid phone number format.", status_code=400
                )

            phone_qs = User.objects.filter(email_or_phone=phone)
            if phone_qs.exists():
                raise CustomSerializerValidationError(
                    "Phone number already exists.", status_code=400
                )

            attrs["phone"] = phone

        return attrs

    @staticmethod
    def get_token(obj):
        """
        Get user token
        """
        user = obj
        user_token = user.get_token_for_user()
        return user_token

    def create(self, validated_data):
        email = validated_data.get("email")
        phone = validated_data.get("phone")
        password = validated_data.get("password")
        full_name = validated_data.get("full_name")
        gender = validated_data.get('gender')

        user = User.objects.create_user(
            email=email,
            phone=phone,
            password=password,
            full_name=full_name,
            gender=gender
        )
        user.save()
        logger.info('user created')
        return user


class UserLoginSerializer(serializers.Serializer):
    """Login serializer for user"""

    email = serializers.CharField(write_only=True, required=False)
    phone = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=True)

    token = serializers.SerializerMethodField(read_only=True)

    @staticmethod
    def get_token(obj):
        """
        Get user token
        """
        user = obj
        user_token = user.get_token_for_user()
        return user_token

    def validate(self, attrs):
        email = attrs.get("email")
        phone = attrs.get("phone")
        password = attrs.get("password")

        # Validate input
        if not email and not phone:
            raise CustomSerializerValidationError(
                "Either a valid email or phone number must be provided.",
                status_code=400
            )

        # Get user by email or phone
        try:
            if email:
                user = User.objects.get(email=email)
            elif phone:
                user = User.objects.get(phone=phone)
        except ObjectDoesNotExist:
            raise CustomSerializerValidationError(
                "User does not exists, create an account.", status_code=400
            )

        # Check user is active
        if not user.is_active:
            raise CustomSerializerValidationError(
                "Account disabled, contact Admin.", status_code=400
            )

        # Ensure user is of type 'General'
        if user.user_type.name != 'General':
            raise CustomSerializerValidationError(
                "Invalid credentials, try again.", status_code=400
            )

        # Check password
        if not check_password(password, user.password):
            raise CustomSerializerValidationError(
                "Invalid credentials, try again.", status_code=400
            )

        # Attach user object to the serializer for token generation
        self.user = user
        return attrs

    def to_representation(self, instance):
        """
        Return the validated data along with token
        """
        return {
            "token": self.get_token(self.user),
        }


class UserProfileSerializer(serializers.ModelSerializer):
    """
    serializer for user profile
    """

    class Meta:
        model = User
        fields = ['email', 'phone', 'full_name', 'gender', 'image']

    def update(self, instance, validated_data):
        instance.full_name = validated_data.get('full_name',
                                                instance.full_name)
        instance.image = validated_data.get('image', instance.image)
        instance.gender = validated_data.get('gender', instance.gender)
        instance.save()
        return instance


class LogoutSerializer(serializers.Serializer):
    """
    serializer for user logout
    """
    refresh_token = serializers.CharField()
    default_error_messages = {
        "bad_token": "Token expired or invalid",
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs

    def save(self, **kwargs):
        try:
            # Blacklist the refresh token
            RefreshToken(self.token).blacklist()
        except Exception:
            raise CustomSerializerValidationError(
                "Token already blacklisted or invalid.",
                status_code=400
            )


class PasswordChangeSerializer(serializers.ModelSerializer):
    """
    serializer for change password
    along with password there will be other parameter
    :param
        old password
        new password
    """
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ['old_password', 'new_password']

    def validate(self, attrs):
        old_password = attrs.get('old_password', None)
        new_password = attrs.get('new_password', None)

        if old_password is not None:
            try:
                user = self.context['request'].user
                attrs['user'] = user
                if not user.check_password(old_password):
                    raise CustomSerializerValidationError(
                        "Old password did not match",
                        status_code=400
                    )
            except User.DoesNotExist:
                raise CustomSerializerValidationError(
                    "User does not exists",
                    status_code=400
                )
        if len(new_password) < 8:
            raise CustomSerializerValidationError(
                "Password length should be 8",
                status_code=400
            )
        if not re.fullmatch(PASSWORD_REGEX, new_password):
            raise CustomSerializerValidationError(
                "Password contain minimum 8 Alphanumeric characters!",
                status_code=400
            )

        return super().validate(attrs)

    def save(self, **kwargs):
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        return user


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for resetting a password.
    Parameters:
        - phone (optional)
        - email (optional)
        - password (required)
        - otp (required)
        - count (required)
    """
    phone = serializers.CharField(write_only=True, required=False)
    email = serializers.EmailField(write_only=True, required=False)
    password = serializers.CharField(required=True, write_only=True)

    class Meta:
        fields = ['phone', 'email', 'password']

    def validate(self, attrs):
        phone = attrs.get("phone", None)
        email = attrs.get("email", None)
        password = attrs.get("password", "")

        # Ensure either phone or email is provided
        if not phone and not email:
            raise CustomSerializerValidationError(
                "Either a valid phone number or email must be provided.",
                status_code=400
            )

        # Phone validation
        if phone:
            if not check_phone_number(phone):
                raise CustomSerializerValidationError(
                    "Phone number is not valid.", status_code=400
                )

            exact_phone_number = get_phone_number(phone)
            phone_len = len(str(exact_phone_number))
            if phone_len != 11:
                raise CustomSerializerValidationError(
                    "Phone number must be 11 digits.", status_code=400
                )

            # Check user by phone
            user = User.objects.filter(
                email_or_phone__iexact=exact_phone_number).first()
            if not user:
                raise CustomSerializerValidationError(
                    "User does not exist.", status_code=400
                )

        # Email validation
        elif email:
            # Check user by email
            user = User.objects.filter(email_or_phone__iexact=email).first()
            if not user:
                raise CustomSerializerValidationError(
                    "User does not exist.", status_code=400
                )

        # Update password for the valid user
        user.set_password(password)
        user.save()

        return attrs


# class OTPSerializer(serializers.Serializer):
#     """
#     Serializer to send OTP to a user's phone or email.
#     """
#     phone = serializers.CharField(required=False, write_only=True)
#     email = serializers.CharField(required=False, write_only=True)
#
#     def validate(self, attrs):
#         phone = attrs.get("phone", "")
#         email = attrs.get("email", "")
#
#         # Ensure at least one of phone or email is provided
#         if not phone and not email:
#             raise CustomSerializerValidationError(
#                 "Either phone or email must be provided.",
#                 status_code=400
#             )
#
#         # Validate phone if provided
#         if phone and not check_phone_number(phone):
#             raise CustomSerializerValidationError(
#                 "Phone number is not valid", status_code=400
#             )
#
#         # Validate email if provided
#         if email and not check_email(email):
#             raise CustomSerializerValidationError(
#                 "Email is not valid", status_code=400
#             )
#
#         return attrs
#
#     def send_otp(self):
#         email = self.validated_data.get("email", "")
#         phone = self.validated_data.get("phone", "")
#
#         otp, count = generate_otp()
#
#         if email:
#             send_otp_email(email, otp)
#         elif phone:
#             send_otp_sms(phone, otp)
#         else:
#             raise CustomSerializerValidationError(
#                 "Neither phone nor email provided.",
#                 status_code=400
#             )
#
#         return otp, count
