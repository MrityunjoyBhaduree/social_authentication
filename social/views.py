import requests
import logging

from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.conf import settings
from social.models import User, UserType
# from social.utils import get_provider_credentials, save_image_from_url
from social.serializers import (
    UserLoginSerializer,
    UserRegisterSerializer,
    UserProfileSerializer,
    LogoutSerializer,
    PasswordResetSerializer,
    PasswordChangeSerializer,
)

logger = logging.getLogger(__name__)


class RegisterView(GenericAPIView):
    """
        API View for Register functionality

            URL: api/v1/users/register/
            Using this url endpoint user can create/register their account.
            Creating account need to valid email address,
            password must be length of minimum 8 Alphanumeric characters,
            Otp and counter
            Here is account creation example

            Method: POST
            :param: {
            "email": "example@gamil.com", or "phone": "01715******"
            "password": "test1234",
            "full_name": "John Doe",
            "gender": "",
            "occupation": "developer",
            "date_of_birth": "1996-12-11",
            "image": null
            "otp": 123456,
            "count": 123456
            }

            :return: {
                "message": "Account successfully created.",
                "data": {
                    "token": {
                        "refresh": refresh_token,
                        "access": access_token
                }
                "status": 201 Created
            }
    """
    serializer_class = UserRegisterSerializer
    http_method_names = ['post']

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Account successfully created.",
                         "data": serializer.data},
                        status=status.HTTP_201_CREATED)


class LoginView(GenericAPIView):
    """
        API View for Login functionality

            Using this url endpoint user can log in their created account.
            When user try to login their account they should provide their
            email id and password
            Here is account login example

            URL: api/v1/users/login/
            :return: {
                "message": "Login successful",
                "data": {
                    "token": {
                        "refresh": refresh_token,
                        "access": access_token
                }
                "status": 200 OK
            }
    """

    serializer_class = UserLoginSerializer
    http_method_names = ['post']

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                "message": "Login successful", "data": serializer.data
            }, status=status.HTTP_200_OK
        )


class ProfileView(GenericAPIView):
    """
        api view for user to view profile and partial update for
        general user profile.

            For view user profile
            URL: api/v1/users/profile/

            Method: GET
            :param: {
            "refresh_token": "HS256(token)",
            }
            :return:{
                "data": {
                    "email": "atik@gmail.com",
                    "phone": null,
                    "full_name": "Atik",
                    "gender": "",
                    "occupation": "manager",
                    "date_of_birth": "1999-10-10",
                    "image": "/media/profile_image/general_user/catlogo.png"
                }
                "status code": 200 OK
            }

            For partial updating user profile

            URL: URL: api/v1/users/profile/
            Method: PATCH
            :param: {
            "full_name": "Mrityunjoy",
            "date_of_birth": "1999-10-10",
            "occupation": "manager"
            "image": "/media/profile_image/general_user/
                    Screenshot_from_2023-03-07_13-48-44.png"
            }
            :return:{
                "message": "Profile update successfully.",
                "data": {
                    "email": "atik@gmail.com",
                    "phone": null,
                    "full_name": "Atik",
                    "gender": "",
                    "occupation": "manager",
                    "date_of_birth": "1999-10-10",
                    "image": "/media/profile_image/general_user/catlogo.png"
                }
                "status code": 200 OK
            }
    """
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        try:
            # Fetch the profile object of the authenticated user
            return User.objects.get(id=self.request.user.id)
        except User.DoesNotExist:
            return None

    def get(self, request, *args, **kwargs):
        user_profile = self.get_object()
        if user_profile:
            serializer = self.serializer_class(user_profile)
            return Response(
                {"data": serializer.data}, status=status.HTTP_200_OK
            )
        return Response(
            {"message": "Profile not found."}, status=status.HTTP_404_NOT_FOUND
        )

    def patch(self, request, *args, **kwargs):
        user_profile = self.get_object()
        if user_profile:
            serializer = self.serializer_class(user_profile, data=request.data,
                                               partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"message": "Profile update successfully.",
                 "data": serializer.data},
                status=status.HTTP_200_OK
            )
        return Response({"message": "Profile not found."},
                        status=status.HTTP_404_NOT_FOUND)


class UserAccountDeleteAPIView(GenericAPIView):
    """
    API for to delete user account
    URL: api/v1/users/account-delete/
    Method: POST
    """
    permission_classes = [IsAuthenticated]
    serializer_class = None
    pagination_class = None

    def post(self, request):
        user_obj = request.user
        user_obj.is_active = False
        user_obj.save()

        return Response({"message": "Your account has been deleted."},
                        status=status.HTTP_200_OK)


class UserLogoutView(GenericAPIView):
    """
        API View for Logout functionality

            URL: api/v1/users/logout/
            Using this url endpoint user can logout their account.
            Here is account logout example

            URL: api/v1/users/logout/
            Method: POST
            :param: {
            "refresh_token": "HS256(token)",
            }
            :return:
                "message": "User Logged out",
                "status": 200 OK,
            }
    """
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "User logged out."},
                        status=status.HTTP_200_OK)


class PasswordResetAPIView(GenericAPIView):
    """
        API used to Set new password

          URL: api/v1/users/password-reset/
          Method: POST
          :param:{
          "otp": "123456",
          "counter": 12324546
          "password1" "pass123",
          "password2" "pass123"
          }
          :return: {
              "message" "Success/Failure",
              "status": "200"
          }
    """
    serializer_class = PasswordResetSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password reset successful'},
                            status=status.HTTP_200_OK)


class PasswordChangeAPIView(GenericAPIView):
    """
        API used to change password


           URL: api/v1/users/password-change/
           Method: POST
          :param:{
          "old_password" "pass123",
          "new_password" "pass123"
          }
          :return: {
              "message" "Success/Failure",
              "status": "200"
          }
    """
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["post"]

    def post(self, request):
        serializer = self.serializer_class(data=request.data,
                                           context={"request": self.request})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'Password change successful'},
                            status=status.HTTP_200_OK)