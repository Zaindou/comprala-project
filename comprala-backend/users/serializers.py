from .models import CompralaUser, PasswordResetToken
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import password_validation
from rest_framework.exceptions import ValidationError
import re


def validate_password(value):
    if len(value) < 8:
        raise serializers.ValidationError(
            "La contraseña debe tener al menos 8 caracteres"
        )

    if not re.search("[A-Z]", value):
        raise serializers.ValidationError(
            "La contraseña debe contener al menos una letra mayúscula"
        )

    if not re.search("[a-z]", value):
        raise serializers.ValidationError(
            "La contraseña debe contener al menos una letra minúscula"
        )

    if not re.search("[0-9]", value):
        raise serializers.ValidationError(
            "La contraseña debe contener al menos un número"
        )

    password_validation.validate_password(value)

    return value


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompralaUser
        fields = ("id", "username", "email", "password")
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate_username(self, value):
        # Max length check
        if len(value) > 15:
            raise serializers.ValidationError(
                "El nombre de usuario no puede tener más de 15 caracteres"
            )

        # Contains "admin" check
        if "admin" in value.lower():
            raise serializers.ValidationError(
                "El nombre de usuario no puede contener la palabra 'admin'"
            )

        # Regex check (only alphanumeric characters allowed)
        if not re.match("^[a-zA-Z0-9]*$", value):
            raise serializers.ValidationError(
                "El nombre de usuario solo puede contener letras y números"
            )

        # Unique check
        if CompralaUser.objects.filter(username=value).exists():
            username = value
            raise serializers.ValidationError(
                f"{username} Este nombre de usuario ya se encuentra registrado."
            )

        return value

    def validate_email(self, value):
        # Regex check
        if not re.match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", value):
            raise serializers.ValidationError(
                "Comprueba tu dirección de email, por favor."
            )

        if CompralaUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este email ya se encuentra registrado.")

        return value

    def validate_password(self, value):
        return validate_password(value)

    def create(self, validated_data):
        user = CompralaUser.objects.create_user(**validated_data)
        return user


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        new_password = attrs.get("new_password")
        confirm_password = attrs.get("confirm_password")

        if new_password != confirm_password:
            raise serializers.ValidationError(
                {"confirm_password": "Las contraseñas no coinciden"}
            )

        validate_password(new_password)

        return attrs

    def save(self):
        try:
            uid = force_str(urlsafe_base64_decode(self.validated_data["uidb64"]))
            user = CompralaUser.objects.get(id=uid)

            # Añade esta verificación
            reset_token = PasswordResetToken.objects.get(user=user)

            if not reset_token.is_valid():
                raise ValidationError({"token": "El token es inválido o ha expirado"})

            password_validation.validate_password(
                self.validated_data["new_password"], user
            )
            user.set_password(self.validated_data["new_password"])
            user.save()

            # Elimina el token una vez utilizado
            reset_token.delete()

        except (
            TypeError,
            ValueError,
            OverflowError,
            User.DoesNotExist,
            PasswordResetToken.DoesNotExist,
        ):
            raise ValidationError({"token": "El token es inválido o ha expirado."})

        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        old_password = attrs.get("old_password")
        new_password = attrs.get("new_password")
        confirm_password = attrs.get("confirm_password")

        if new_password != confirm_password:
            raise serializers.ValidationError(
                {"confirm_password": "Las contraseñas no coinciden"}
            )

        validate_password(new_password)

        return attrs

    def save(self, user):
        if not user.check_password(self.validated_data["old_password"]):
            raise serializers.ValidationError(
                {"old_password": "La contraseña actual no es correcta"}
            )

        user.set_password(self.validated_data["new_password"])
        user.save()

        return user
