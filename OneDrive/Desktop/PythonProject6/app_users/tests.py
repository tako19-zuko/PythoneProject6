from rest_framework.test import APITestCase
from django.urls import reverse
from .models import User

class UserTests(APITestCase):
    def setUp(self):
        self.register_url = reverse('user-list')  # router registers 'users'
        self.token_url = reverse('token_obtain_pair')
    def test_register_requires_contact(self):
        data = {"password":"StrongPass123!"}
        resp = self.client.post(self.register_url, data)
        self.assertEqual(resp.status_code, 400)

    def test_register_and_login(self):
        data = {"email":"test@example.com","password":"StrongPass123!"}
        resp = self.client.post(self.register_url, data)
        self.assertEqual(resp.status_code, 201)
        # login
        resp2 = self.client.post(self.token_url, {"email":"test@example.com","password":"StrongPass123!"})
        self.assertEqual(resp2.status_code, 200)
        self.assertIn('access', resp2.data)

    def test_verification_flow(self):
        # create user object directly
        user = User.objects.create_user(email="v@test.com", password="StrongPass123!")
        user.verification_token = "token123"
        user.verification_token_created_at = user.date_joined
        user.save()
        url = reverse('user-verify')  # action name created by router: 'user-verify'
        resp = self.client.post(url, {"token":"token123","contact_type":"email"})
        self.assertEqual(resp.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)

    def test_recovery_flow(self):
        user = User.objects.create_user(email="r@test.com", password="StrongPass123!")
        user.recovery_question = "pet?"
        user.set_recovery_answer("fluffy")
        user.save()
        url_recover = reverse('user-recover')
        resp = self.client.post(url_recover, {"identifier":"r@test.com","answer":"fluffy"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('reset_token', resp.data)
        token = resp.data['reset_token']
        url_reset = reverse('user-reset-password')
        resp2 = self.client.post(url_reset, {"token":token, "password":"NewStrongPass123!"})
        self.assertEqual(resp2.status_code, 200)