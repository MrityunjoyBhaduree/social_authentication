import re
import logging
import re
import time
import base64
import requests

# from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
# from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
# from allauth.socialaccount.models import SocialApp

from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.conf import settings


logger = logging.getLogger(__name__)


def check_phone_number(text):
    """
    function for check phone number is valid or not
    :param text:
    :return: True if number is valid, else False
    Number formats
    +8801812598624, 008801812598624, 01812598624,01712598624,
     01672598624,01919598624,01419598624,01319598624,
    """
    phone_number_regex = r'^(?:(?:\+|0{2})8{2}|01)?\d{11}$'
    if re.fullmatch(phone_number_regex, text):
        return True
    else:
        return False


def get_phone_number(number):
    """

    :param number: +88018XXXXXXXX or starts with 0088
    :return: exact phone number removing country code like: 88018XXXXXXXX,
     removing extra country code
    """
    country_code_regex = r"(0088|\+88)"
    exact_number = re.sub(country_code_regex, "", number, count=1)
    return exact_number


def check_email(email):
  regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
  if re.fullmatch(regex, email):
    return True
  else:
    return False