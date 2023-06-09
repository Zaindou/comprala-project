from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.db import models
from django.conf import settings  # No olvides importar settings


class CompralaUser(AbstractUser):
    email = models.EmailField(unique=True, blank=False)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username


User = get_user_model()


class PasswordResetToken(models.Model):
    user = models.OneToOneField(
        CompralaUser, on_delete=models.CASCADE, related_name="reset_token"
    )
    token = models.CharField(
        max_length=255, unique=True, default=get_random_string(length=22)
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return timezone.now() - self.created_at < timezone.timedelta(days=1)

    def __str__(self):
        return f"{self.user.username} - {self.token}"


class EmailVerificationToken(models.Model):
    user = models.OneToOneField(
        CompralaUser, on_delete=models.CASCADE, related_name="email_token"
    )
    token = models.CharField(
        max_length=255, unique=True, default=get_random_string(length=22)
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return timezone.now() - self.created_at < timezone.timedelta(days=1)

    def __str__(self):
        return f"{self.user.username} - {self.token}"
