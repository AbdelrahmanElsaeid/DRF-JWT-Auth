
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        custom_response_data = {
            'message': ''
        }

        # Flatten error messages into a single string
        
        if isinstance(response.data, dict):
            error_messages = []
            for key, value in response.data.items():
                if isinstance(value, list):
                    error_messages.extend(value)
                else:
                    error_messages.append(value)
            custom_response_data['message'] = ' '.join(str(msg) for msg in error_messages)
        else:
            custom_response_data['message'] = response.data

        response.data = custom_response_data

    return response