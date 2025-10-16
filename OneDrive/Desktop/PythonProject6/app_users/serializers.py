from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
import secrets

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    recovery_answer = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ('id','email','mobile','first_name','last_name','password','recovery_question','recovery_answer')

    def validate(self, data):
        if not data.get('email') and not data.get('mobile'):
            raise serializers.ValidationError("Provide at least email or mobile.")
        password = data.get('password')
        validate_password(password)
        return data

    def create(self, validated_data):
        recovery_answer = validated_data.pop('recovery_answer', None)
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        if recovery_answer:
            user.set_recovery_answer(recovery_answer)
        # create simple verification token (non-production: implement expiry & send)
        user.verification_token = secrets.token_urlsafe(32)
        user.verification_token_created_at = timezone.now()
        user.save(update_fields=['verification_token','verification_token_created_at'])
        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        read_only_fields = ('id','is_email_verified','is_mobile_verified','date_joined')
        fields = ('id','email','mobile','first_name','last_name','is_email_verified','is_mobile_verified','date_joined')

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name','last_name','email','mobile','recovery_question')

    def validate(self, data):
        # Prevent removing both contacts
        instance = getattr(self, 'instance', None)
        email = data.get('email', instance.email if instance else None)
        mobile = data.get('mobile', instance.mobile if instance else None)
        if not email and not mobile:
            raise serializers.ValidationError("User must have at least an email or mobile.")
        return data

class VerifySerializer(serializers.Serializer):
    token = serializers.CharField()
    contact_type = serializers.ChoiceField(choices=['email','mobile'])
    from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
    from django.contrib.auth import authenticate
    from django.contrib.auth import get_user_model

    class EmailOrMobileTokenObtainPairSerializer(TokenObtainPairSerializer):
        @classmethod
        def get_token(cls, user):
            token = super().get_token(user)
            token['id'] = str(user.id)
            token['email'] = user.email
            return token

        def validate(self, attrs):
            # attrs will have 'username' and 'password' by default; we'll accept 'identifier'
            identifier = attrs.get('username') or attrs.get('identifier')
            password = attrs.get('password')
            if identifier is None or password is None:
                raise serializers.ValidationError("Must include identifier and password.")
            # try email first then mobile
            User = get_user_model()
            user = None
            if '@' in identifier:
                try:
                    user_obj = User.objects.get(email__iexact=identifier)
                    user = authenticate(self.context['request'], username=user_obj.email, password=password)
                except User.DoesNotExist:
                    user = None
            if user is None:
                # fallback to mobile
                try:
                    user_obj = User.objects.get(mobile=identifier)
                    user = authenticate(self.context['request'], username=user_obj.email or user_obj.mobile,
                                        password=password)
                except User.DoesNotExist:
                    user = None
            if user is None:
                raise serializers.ValidationError("Invalid credentials")
            attrs['user'] = user
            data = super().validate({'username': user.email or user.mobile, 'password': password})
            return data


class EmailOrMobileTokenObtainPairSerializer:
    pass
from rest_framework import serializers
from django.contrib.auth.hashers import check_password
from .models import User, VerificationToken, PasswordResetToken
import uuid

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    recovery_answer = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'mobile', 'password', 'recovery_question', 'recovery_answer', 'is_verified']
        read_only_fields = ['is_verified']

    def create(self, validated_data):
        recovery_answer = validated_data.pop('recovery_answer')
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.set_recovery_answer(recovery_answer)
        user.save()
        return user

class VerificationRequestSerializer(serializers.Serializer):
    contact_type = serializers.ChoiceField(choices=['email','mobile'])

class VerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    contact_type = serializers.CharField()

class RecoverySerializer(serializers.Serializer):
    identifier = serializers.CharField()
    answer = serializers.CharField()

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()