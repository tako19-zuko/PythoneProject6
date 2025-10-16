from django.db import models
from django.conf import settings
import uuid

class Verification(models.Model):
    CONTACT_EMAIL = 'email'
    CONTACT_MOBILE = 'mobile'
    CONTACT_CHOICES = [
        (CONTACT_EMAIL, 'Email'),
        (CONTACT_MOBILE, 'Mobile'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='verifications')
    contact_type = models.CharField(max_length=10, choices=CONTACT_CHOICES)
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    sent_via = models.CharField(max_length=50, blank=True, null=True)  # optional: provider (smtp, twilio)
    meta = models.JSONField(blank=True, null=True)  # optional audit info

    class Meta:
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user','contact_type']),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at

    def mark_used(self):
        self.used = True
        self.save(update_fields=['used'])
        from django.contrib.auth.hashers import make_password, check_password
        class User(...):
            # fields...
            recovery_answer_hashed = models.CharField(max_length=128, blank=True, null=True)

            def set_recovery_answer(self, raw_answer):
                if raw_answer:
                    self.recovery_answer_hashed = make_password(raw_answer)
                    self.save(update_fields=['recovery_answer_hashed'])

            def check_recovery_answer(self, raw_answer):
                if not self.recovery_answer_hashed:
                    return False
                return check_password(raw_answer, self.recovery_answer_hashed)


class User:
    pass
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from .managers import UserManager

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, null=True, blank=True)
    mobile = models.CharField(max_length=20, unique=True, null=True, blank=True)
    recovery_question = models.CharField(max_length=255)
    recovery_answer_hashed = models.CharField(max_length=255)

    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def set_recovery_answer(self, raw_answer):
        self.recovery_answer_hashed = make_password(raw_answer)

    def str(self):
        return self.email or self.mobile

class VerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    contact_type = models.CharField(max_length=20, choices=(('email','email'),('mobile','mobile')))
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)