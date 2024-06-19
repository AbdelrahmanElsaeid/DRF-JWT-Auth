from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.utils.translation import gettext as _
from django.core.exceptions import ValidationError


class UserSerializer(serializers.ModelSerializer):    
    class Meta:
        model = User
        fields = ['id', 'username']





class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ["email", "username", "first_name", "last_name", 'password', 'password2'] 

    def validate_username(self, value):
        """Validate the 'username' field."""
        if len(value) < 3:
            raise serializers.ValidationError(_("username must be at least 3 characters long."))
        return value    


    def validate(self, attrs):
        """Validate password confirmation."""
        # Check if passwords match
        
        email = attrs.get('email')
        validate_email(email)
        if attrs['password'] != attrs['password2']:
            #raise serializers.ValidationError(_("Passwords do not match"))
            raise serializers.ValidationError({"non_field_errors": _("Passwords do not match")})


            
        return attrs  
    
   

    def create(self, validated_data):
        """Create a new user with the validated data."""
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
        )

        # Set the password and save the user
        user.set_password(validated_data['password'])
        user.save()

        return user

         

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128, style={"input_type": "password"})



class AccountActivationSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6) 




class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetVerifySerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password], style={"input_type": "password"}) 
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"password": _("Password fields didn't match.")})
        return attrs  



class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password], style={"input_type": "password"})
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        user = self.context["request"].user

        if not user.check_password(attrs["old_password"]):
            raise serializers.ValidationError({"old_password": _("Password is incorrect.")})
        
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"password": _("Password fields didn't match.")})

        return attrs
