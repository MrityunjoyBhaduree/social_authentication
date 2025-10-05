import logging

from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import serializers

logger = logging.getLogger(__name__)


class BaseCustomException(APIException):
    error = None
    status_code = None

    def __init__(self, error_message, status_code):
        super().__init__(error_message, status_code)
        self.error = error_message
        self.status_code = status_code


class CustomSerializerValidationError(BaseCustomException):

    def __init__(self, err_msg, status_code):
        super().__init__(err_msg, status_code)


class CustomAPIError(BaseCustomException):

    def __init__(self, err_msg, status_code):
        super().__init__(err_msg, status_code)


class CustomException(Exception):
    status_code = 400
    default_detail = 'An error occurred'


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        if isinstance(exc, serializers.ValidationError):
            if hasattr(exc, 'detail') and isinstance(exc.detail, dict):

                # If the error is a dictionary,
                # it contains the error messages for each field
                errors = []
                for field, messages in exc.detail.items():
                    if isinstance(messages, list):
                        errors.append({'field': field, 'message': messages[0]})
                        break
                    elif isinstance(messages, dict):
                        for m in messages.items():
                            errors.append({'field': m[0], 'message': m[1][0]})
                            break
                response.data = {
                    "error": f"{errors[0]['field']}, {errors[0]['message']}",
                    "status": CustomException.status_code
                }
            else:
                response.data = {
                    'error': str(CustomException.default_detail),
                    'status': CustomException.status_code
                }
        else:
            error_message = response.data.get('detail', 'Error')
            if error_message is not None:
                response.data['error'] = error_message
            else:
                response.data['error'] = str(exc)
            response.data['status'] = response.status_code
            try:
                response.data.pop("detail", None)
                response.data.pop("code", None)
                response.data.pop("messages", None)
            except Exception:
                pass
    return response
