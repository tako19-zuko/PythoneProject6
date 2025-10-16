from rest_framework import viewsets, status, permissions, decorators
from rest_framework.response import Response
from .models import User, Verification
from .serializers import UserRegisterSerializer, UserSerializer, UserUpdateSerializer, VerifySerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import check_password
VERIFICATION_EXPIRY_MINUTES = 60 * 24  # example: 24 hours
class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # safe methods allowed for staff only? We'll restrict reading: owner or staff
        if request.method in permissions.SAFE_METHODS:
            return obj == request.user or request.user.is_staff
        return obj == request.user or request.user.is_staff
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    serializer_class = UserSerializer
    def get_serializer_class(self):
        if self.action == 'create':
            return UserRegisterSerializer
        if self.action in ['partial_update','update']:
            return UserUpdateSerializer
        return UserSerializer
    def create(self, request, *args, **kwargs):
        # registration
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        data = UserSerializer(user, context={'request': request}).data
        return Response(data, status=status.HTTP_201_CREATED)
    def perform_destroy(self, instance):
        # soft-delete behaviour option: here full delete
        instance.delete()
    @decorators.action(detail=False, methods=['post'], url_path='verify')
    def verify(self, request):
        s = VerifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        token = s.validated_data['token']
        contact_type = s.validated_data['contact_type']
        try:
            user = User.objects.get(verification_token=token)
        except User.DoesNotExist:
            return Response({"detail":"Invalid token"}, status=400)
        created = user.verification_token_created_at
        if not created or (timezone.now() - created) > timedelta(minutes=VERIFICATION_EXPIRY_MINUTES):
            return Response({"detail":"Token expired"}, status=400)
        if contact_type == 'email':
            user.is_email_verified = True
        else:
            user.is_mobile_verified = True
        user.verification_token = None
        user.verification_token_created_at = None
        user.save(update_fields=['is_email_verified','is_mobile_verified','verification_token','verification_token_created_at'])
        return Response({"detail":"Verified"}, status=200)
    @decorators.action(detail=False, methods=['post'], url_path='request-verification')
    def request_verification(self, request):
        contact_type = request.data.get('contact_type')
        if contact_type not in ['email','mobile']:
            return Response({"detail":"contact_type must be 'email' or 'mobile'."}, status=400)
        # Require authentication to request verification on own account
        if not request.user.is_authenticated:
            return Response({"detail":"Authentication required"}, status=401)
        user = request.user
        if contact_type == 'email' and not user.email:
            return Response({"detail":"No email set"}, status=400)
        if contact_type == 'mobile' and not user.mobile:
            return Response({"detail":"No mobile set"}, status=400)
        import secrets
        user.verification_token = secrets.token_urlsafe(32)
        user.verification_token_created_at = timezone.now()
        user.save(update_fields=['verification_token','verification_token_created_at'])
        # TODO: send token by email/SMS in production
        return Response({"detail":"Verification token created", "token": user.verification_token})
    @decorators.action(detail=False, methods=['post'], url_path='recover')
    def recover(self, request, models=None):
        # Recover by email or mobile + matching recovery question/answer
        identifier = request.data.get('identifier')  # email or mobile
        answer = request.data.get('answer')
        if not identifier or not answer:
            return Response({"detail":"Provide identifier and answer"}, status=400)
        try:
            user = User.objects.get(models.Q(email=identifier) | models.Q(mobile=identifier))
        except User.DoesNotExist:
            return Response({"detail":"User not found"}, status=404)
        if not user.check_recovery_answer(answer):
            return Response({"detail":"Wrong answer"}, status=400)
        # create a temporary token or allow password reset flow. We'll return a temporary token for reset.
        import secrets
        tmp = secrets.token_urlsafe(32)
        user.verification_token = tmp
        user.verification_token_created_at = timezone.now()
        user.save(update_fields=['verification_token','verification_token_created_at'])
        return Response({"detail":"Recovery verified", "reset_token": tmp})
    @decorators.action(detail=False, methods=['post'], url_path='reset-password')
    def reset_password(self, request):
        token = request.data.get('token')
        new_password = request.data.get('password')
        if not token or not new_password:
            return Response({"detail":"Token and new password required"}, status=400)
        try:
            user = User.objects.get(verification_token=token)
        except User.DoesNotExist:
            return Response({"detail":"Invalid token"}, status=400)
        # check expiry
        created = user.verification_token_created_at
        if not created or (timezone.now() - created) > timedelta(minutes=VERIFICATION_EXPIRY_MINUTES):
            return Response({"detail":"Token expired"}, status=400)
        # validate password
        from django.contrib.auth.password_validation import validate_password
        try:
            validate_password(new_password, user)
        except Exception as e:
            return Response({"detail":str(e)}, status=400)
        user.set_password(new_password)
        user.verification_token = None
        user.verification_token_created_at = None
        user.save(update_fields=['password','verification_token','verification_token_created_at'])
        return Response({"detail":"Password reset successful"}, status=200)
# JWT Token view
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        token['id'] = str(user.id)
        return token
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    from .models import Verification
    from .tasks import create_and_send_verification
    from django.utils import timezone
    from datetime import timedelta

    @decorators.action(detail=False, methods=['post'], url_path='request-verification')
    def request_verification(self, request, create_and_send_verification=None):
        contact_type = request.data.get('contact_type')
        if contact_type not in ['email', 'mobile']:
            return Response({"detail": "contact_type must be 'email' or 'mobile'."}, status=400)
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required"}, status=401)
        user = request.user
        destination = user.email if contact_type == 'email' else user.mobile
        if not destination:
            return Response({"detail": "Contact not set"}, status=400)

        # Create verification model row + send via background task
        from django.utils import timezone
        from datetime import timedelta
        from django.conf import settings
        # set expiry (configurable)
        ttl_minutes = getattr(settings, 'VERIFICATION_TTL_MINUTES', 24 * 60)
        expires_at = timezone.now() + timedelta(minutes=ttl_minutes)

        # create DB entry (token stored securely)
        import secrets
        token = secrets.token_urlsafe(48)
        ver = Verification.objects.create(
            user=user,
            contact_type=contact_type,
            token=token,
            created_at=timezone.now(),
            expires_at=expires_at,
            sent_via='queued'
        )

        # enqueue task to actually send (task will generate its own token if you prefer)
        create_and_send_verification.delay(str(user.id), contact_type, destination,
                                           provider='email' if contact_type == 'email' else 'sms')

        # IMPORTANT: do not return the token in response
        return Response({"detail": "Verification requested. Check your contact for a message."}, status=202)

    corators.action(detail=False, methods=['post'], url_path='verify')

    def verify(self, request):
        token = request.data.get('token')
        contact_type = request.data.get('contact_type')
        if not token or contact_type not in ['email', 'mobile']:
            return Response({"detail": "Token and contact_type required."}, status=400)
        try:
            ver = Verification.objects.select_related('user').get(token=token, contact_type=contact_type)
        except Verification.DoesNotExist:
            return Response({"detail": "Invalid token"}, status=400)
        if ver.used:
            return Response({"detail": "Token already used"}, status=400)
        if ver.is_expired():
            return Response({"detail": "Token expired"}, status=400)
        # mark verification
        user = ver.user
        if contact_type == 'email':
            user.is_email_verified = True
        else:
            user.is_mobile_verified = True
        user.save(update_fields=['is_email_verified', 'is_mobile_verified'])
        ver.mark_used()
        return Response({"detail": "Verified"}, status=200)
@decorators.action(detail=False, methods=['post'], url_path='recover')
def recover(self, request):
    identifier = request.data.get('identifier')
    answer = request.data.get('answer')
    if not identifier or not answer:
        return Response({"detail":"Provide identifier and answer"}, status=400)
    try:
        user = User.objects.get(models.Q(email=identifier) | models.Q(mobile=identifier))
    except User.DoesNotExist:
        return Response({"detail":"User not found"}, status=404)
    if not user.check_recovery_answer(answer):
        return Response({"detail":"Wrong answer"}, status=400)
    # create verification record (for password reset)
    import secrets
    token = secrets.token_urlsafe(48)
    ver = Verification.objects.create(
        user=user,
        contact_type='email' if user.email else 'mobile',
        token=token,
        created_at=timezone.now(),
        expires_at=timezone.now() + timedelta(minutes=getattr(settings,'RECOVERY_TTL_MINUTES',60)),
        sent_via='recovery'
    )
    # send token via email/sms in background
    create_and_send_verification.delay(str(user.id), ver.contact_type, user.email or user.mobile, provider='email' if user.email else 'sms')
    return Response({"detail":"Recovery initiated. Check your contact."}, status=202)
@decorators.action(detail=False, methods=['post'], url_path='reset-password')
def reset_password(self, request):
    token = request.data.get('token')
    new_password = request.data.get('password')
    if not token or not new_password:
        return Response({"detail":"Token and new password required"}, status=400)
    try:
        ver = Verification.objects.select_related('user').get(token=token, sent_via='recovery')
    except Verification.DoesNotExist:
        return Response({"detail":"Invalid token"}, status=400)
    if ver.is_expired() or ver.used:
        return Response({"detail":"Token invalid/expired"}, status=400)
    user = ver.user
    # validate password
    from django.contrib.auth.password_validation import validate_password
    try:
        validate_password(new_password, user)
    except Exception as e:
        return Response({"detail":str(e)}, status=400)
    user.set_password(new_password)
    user.save(update_fields=['password'])
    ver.mark_used()
    return Response({"detail":"Password reset successful"}, status=200)
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import EmailOrMobileTokenObtainPairSerializer

class EmailOrMobileTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailOrMobileTokenObtainPairSerializer
from .throttles import VerificationThrottle, RecoverThrottle

@decorators.action(detail=False, methods=['post'], url_path='request-verification')
@throttle_classes([VerificationThrottle])
def request_verification(request):
    # Your logic here
    return Response({"message": "Verification requested."})
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from .models import User, VerificationToken, PasswordResetToken
from .serializers import UserSerializer, VerificationRequestSerializer, VerificationSerializer, RecoverySerializer, ResetPasswordSerializer
import uuid
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)
class RequestVerificationView(generics.GenericAPIView):
    serializer_class = VerificationRequestSerializer
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = str(uuid.uuid4())
        VerificationToken.objects.create(
            user=request.user,
            token=token,
            contact_type=serializer.validated_data['contact_type']
        )
        # აქ შეგიძლია ჩასვა Email/SMS გაგზავნა Celery-ით
        return Response({'detail': 'Verification token generated', 'token (dev only)': token})
class VerifyView(generics.GenericAPIView):
    serializer_class = VerificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']
        vt = VerificationToken.objects.filter(token=token, user=request.user, is_used=False).first()
        if not vt:
            return Response({'detail':'Invalid token'}, status=400)
        vt.is_used = True
        vt.save()
        request.user.is_verified = True
        request.user.save()
        return Response({'detail':'Verified successfully'})
class RecoveryView(generics.GenericAPIView):
    serializer_class = RecoverySerializer
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data['identifier']
        answer = serializer.validated_data['answer']
        user = User.objects.filter(email=identifier).first() or User.objects.filter(mobile=identifier).first()
        if not user:
            return Response({'detail':'User not found'}, status=404)
        if not check_password(answer, user.recovery_answer_hashed):
            return Response({'detail':'Invalid answer'}, status=400)
        token = str(uuid.uuid4())
        PasswordResetToken.objects.create(user=user, token=token)
        return Response({'reset_token': token})
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']
        prt = PasswordResetToken.objects.filter(token=token, is_used=False).first()
        if not prt:
            return Response({'detail':'Invalid or used token'}, status=400)
        user = prt.user
        user.set_password(new_password)
        user.save()
        prt.is_used = True
        prt.save()
        return Response({'detail':'Password reset successful'})

    from .tasks import send_verification_email, send_sms_verification

    class RequestVerificationView(generics.GenericAPIView):
        serializer_class = VerificationRequestSerializer
        permission_classes = [permissions.IsAuthenticated]

        def post(self, request):
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            token = str(uuid.uuid4())
            contact_type = serializer.validated_data['contact_type']
            VerificationToken.objects.create(
                user=request.user,
                token=token,
                contact_type=contact_type
            )
            if contact_type == 'email' and request.user.email:
                send_verification_email.delay(request.user.email, token)
            elif contact_type == 'mobile' and request.user.mobile:
                send_sms_verification.delay(request.user.mobile, token)

            return Response({'detail': 'Verification token sent'})