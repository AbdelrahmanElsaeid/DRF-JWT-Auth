from .serializers import AccountActivationSerializer, LoginSerializer, SignUpSerializer , PasswordResetSerializer, PasswordResetVerifySerializer, PasswordChangeSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics
from django.contrib.auth import authenticate, get_user_model,login, logout
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from .models import ActivationCode
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .tasks import send_email_task
from django.utils.translation import gettext as _
from .models import User
from django.core.validators import validate_email
import random
import string

# Create your views here.



class SignUp(generics.CreateAPIView):
    serializer_class = SignUpSerializer

    def create(self, request, *args, **kwargs):
        
        email = request.data.get('email')
        username = request.data.get('username')

        # check if email and username already exists
        user = get_user_model().objects.filter(Q(email=email) | Q(username=username)).first()
       
        if user:
            if user.email == email:
                return Response({'status': 'error', "message": _("Email already exists")}, status=status.HTTP_400_BAD_REQUEST)
            if user.username == username:
                return Response({'status': 'error', "message": _("Username already exists")}, status=status.HTTP_400_BAD_REQUEST)
        
       
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            
            user = serializer.save()

            activation_code = ActivationCode(user=user)

            activation_code.create_activation_code()
            
            # Send Email
            subject = "Active Your Account"
            message = f"Your activation code is {activation_code.activation_code}"
            from_email = "<my email>"
            to_email = [email.replace('\n', '').replace('\r', '')]

            send_email_task.delay(subject, message, from_email,to_email, fail_silently=True)

            
            # try:
            #     send_email_task.delay(subject, message, from_email,to_email, fail_silently=True)
            # except Exception:
            #     return Response({"status": "error","message": _("Error sending email")}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response(
                {"status":"success", "message": _("Account created, check your email for activation code")}, status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    




class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        # Authenticate user
        user = authenticate(request, email=email, password=password)

        if user is not None and user.email_comfirmed:
            login(request, user)

            # Generate tokens
            refresh = RefreshToken.for_user(user)

            # Add additional data to the access token payload
            refresh.payload['email'] = user.email
            refresh.payload['username'] = user.username

            return Response({
                'status': 'success',
                'message': _("Login successful"),
                "tokens": {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            }, status=status.HTTP_200_OK)
        
        elif user is not None and not user.email_comfirmed:
                return Response({"status": "Error","message": _("Email not confirmed, please activate your account")}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"status": "Error", "message": _("Invalid Email or password")}, status=status.HTTP_401_UNAUTHORIZED)

        
    
class AccountActivation(generics.CreateAPIView):
    serializer_class = AccountActivationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            activation_code = serializer.validated_data["code"]
            email_confirmed = ActivationCode.objects.filter(activation_code=activation_code).first()
            if email_confirmed:
                if email_confirmed.verify_activation_code(activation_code):
                    return Response({"status": "success","message": _("Account Activated")}, status=status.HTTP_200_OK)
                else:
                    return Response({"status": "Error","message": _("Invalid activation code")}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"status": "Error","message": _("Invalid activation code")}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

def generate_verification_code():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

class PasswordReset(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            try:
                user = get_user_model().objects.get(email=email)
            except get_user_model().DoesNotExist:
                return Response({"status": "Error","message": _("Email not found")}, status=status.HTTP_400_BAD_REQUEST)
            code = generate_verification_code()
            user.email_verification_code = code
            user.save()

            subject = "Password Reset"
            message = f"Your password reset code is {code}"
            from_email = "<my email>"
            to_email = [email.replace('\n', '').replace('\r', '')]

            try:
                send_email_task.delay(subject, message, from_email,to_email, fail_silently=True)
            except Exception:
                return Response({"status": "error","message": _("Error sending email")}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({"status":"success","message": _("Password reset code sent to email")}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
                

class PasswordResetVerify(generics.CreateAPIView):
    serializer_class = PasswordResetVerifySerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data["new_password"]
            code = serializer.validated_data["code"]
            try:
                user = get_user_model().objects.get(email_verification_code=code)
            except get_user_model().DoesNotExist:
                return Response({"status": "error","message": _("Invalid code")}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.email_verification_code = None
            user.save()
            return Response({"status": "success","message": _("Password reset successful")}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 


class PasswordChange(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            new_password = serializer.validated_data["new_password"]
            old_password = serializer.validated_data["old_password"]
            if not user.check_password(old_password):
                return Response({"status": "error","message": _("Invalid password")}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            return Response({"status": "success","message": _("Password changed successfully")}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)                 
    

