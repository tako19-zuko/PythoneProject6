from dis import name

from PythoneProject2.celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import Verification
import secrets

VERIFICATION_TTL_MINUTES = 60 * 24  # 24 hours default

@shared_task(bind=True)
def create_and_send_verification(self, user_id, contact_type, destination, provider='email'):
    """
    Creates a Verification row and sends it via provider.
    IMPORTANT: This task should NOT return the token to API response.
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return {'error':'user-not-found'}

    token = secrets.token_urlsafe(48)
    now = timezone.now()
    expires_at = now + timedelta(minutes=VERIFICATION_TTL_MINUTES)

    ver = Verification.objects.create(
        user=user,
        contact_type=contact_type,
        token=token,
        created_at=now,
        expires_at=expires_at,
        sent_via=provider,
        meta={'destination': destination}
    )

    # send by provider (email / sms)
    if provider == 'email':
        # Use Django email backend (or integrate SMTP here)
        from django.core.mail import send_mail
        subject = "Verify your contact"
        message = f"Please verify: use token {token}"  # in prod send link instead of token
        send_mail(subject, message, None, [destination], fail_silently=False)
    elif provider == 'sms':
        # Implement SMS provider integration (e.g., Twilio)
        # Example pseudo-code:
        # twilioclient.messages.create(to=destination, from=TWILIO_FROM, body=f"Verify: {token}")
        pass

    # DO NOT return token in API response — token remains in DB and is sent externally.
    return {'status':'sent', 'verification_id': str(ver.id)}
from PythoneProject2.celery import shared_task
from django.core.mail import send_mail
import logging

logger = logging.getLogger(name)

@shared_task
def send_verification_email(to_email, token):
    subject = "Your Verification Token"
    message = f"Your verification token is: {token}"
    from_email = "no-reply@example.com"
    try:
        send_mail(subject, message, from_email, [to_email])
        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Email failed: {e}")

@shared_task
def send_sms_verification(to_number, token):
    # აქ შეგიძლია დაამატო რეალური Twilio ან სხვა SMS სერვისი
    logger.info(f"Mock SMS sent to {to_number}: {token}")