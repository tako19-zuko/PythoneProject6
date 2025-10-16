from rest_framework.throttling import SimpleRateThrottle

class VerificationThrottle(SimpleRateThrottle):
    scope = 'verification'

class RecoverThrottle(SimpleRateThrottle):
    scope = 'recover'