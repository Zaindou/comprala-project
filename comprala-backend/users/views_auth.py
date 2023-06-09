from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework.views import APIView
from .serializers import (
    UserSerializer,
    PasswordResetConfirmSerializer,
    ChangePasswordSerializer,
)
from .models import CompralaUser, PasswordResetToken, EmailVerificationToken
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model
from rest_framework import exceptions
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from django.db.models import Q
from django.urls import reverse


class UserCreate(generics.CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serialezer = self.get_serializer(data=request.data)
        serialezer.is_valid(raise_exception=True)
        self.perform_create(serialezer)
        headers = self.get_success_headers(serialezer.data)
        return Response(
            serialezer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def perform_create(self, serializer):
        user = CompralaUser.objects.create_user(
            username=serializer.validated_data["username"],
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )

        # Crea el token de verificación de correo electrónico
        token, created = EmailVerificationToken.objects.get_or_create(user=user)

        # Construye la URL de verificación de correo electrónico
        verification_url = self.request.build_absolute_uri(
            reverse("verify_email", args=[token.token])
        )

        # Envía el correo electrónico de verificación
        send_mail(
            "Verificación de correo electrónico",
            f"Hola {user.username},\n\nPor favor haz click en el siguiente enlace para verificar tu correo electrónico:\n\n{verification_url}",
            "ghost@comprala.co",
            [user.email],
            fail_silently=False,
        )


class VerifyEmailView(APIView):
    def get(self, request, *args, **kwargs):
        token = self.kwargs["token"]

        try:
            email_token = EmailVerificationToken.objects.get(token=token)
        except EmailVerificationToken.DoesNotExist:
            return Response(
                {
                    "error": "El token de verificación de correo electrónico no es válido o ha expirado."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not email_token.is_valid():
            return Response(
                {
                    "error": "El token de verificación de correo electrónico ha expirado."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Si llegamos aquí, el token es válido y no ha expirado
        user = email_token.user
        user.is_verified = True
        user.save()

        # Elimina el token después de su uso
        email_token.delete()

        return Response(
            {"message": "El correo electrónico ha sido verificado correctamente."}
        )


class ResendVerificationEmailView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        if not email:
            return Response(
                {"error": "Debes ingresar tu email."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = CompralaUser.objects.get(email=email)
        except CompralaUser.DoesNotExist:
            return Response(
                {"error": "No hemos encontrado tu usuario."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_verified:
            return Response(
                {"error": "Tu correo electrónico ya ha sido verificado."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Crea el token de verificación de correo electrónico
        token, created = EmailVerificationToken.objects.get_or_create(user=user)

        # Construye la URL de verificación de correo electrónico
        verification_url = self.request.build_absolute_uri(
            reverse("verify_email", args=[token.token])
        )

        # Envía el correo electrónico de verificación
        send_mail(
            "Verificación de correo electrónico",
            f"Hola {user.username},\n\nPor favor haz click en el siguiente enlace para verificar tu correo electrónico:\n\n{verification_url}",
            "ghost@comprala.co",
            [user.email],
            fail_silently=False,
        )

        return Response(
            {"message": "El correo electrónico de verificación ha sido enviado."}
        )


User = get_user_model()


class CustomAuthTokenView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Debes ingresar tu email y contraseña."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "No hemos encontrado tu usuario."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.check_password(password):
            Token.objects.filter(user=user).delete()  # Eliminar el token si ya existe
            token, created = Token.objects.get_or_create(user=user)
            return Response(
                {"token": token.key, "user_id": user.pk, "email": user.email}
            )
        else:
            return Response(
                {"error": "Tu contraseña o email son incorrectos."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class Logout(APIView):
    def post(self, request, *args, **kwargs):
        try:
            token = request.headers.get("Authorization").split(" ")[1]
            Token.objects.filter(key=token).delete()
            return Response(
                {"message": "Has cerrado sesión exitosamente."},
                status=status.HTTP_200_OK,
            )
        except:
            return Response(
                {"error": "No se ha podido cerrar sesión."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer

    def get_object(self, queryset=None):
        return self.request.user

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            try:
                serializer.save(user=self.object)
                return Response(
                    {"message": "Contraseña actualizada exitosamente."},
                    status=status.HTTP_200_OK,
                )
            except serializers.ValidationError as e:
                return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(generics.CreateAPIView):
    def create(self, request, *args, **kwargs):
        email = request.data.get("email")

        try:
            user = CompralaUser.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"message": "No existe una cuenta asociada a este email."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if user:
            # Elimina cualquier token existente para este usuario
            PasswordResetToken.objects.filter(Q(user=user)).delete()

            # Ahora, crea un nuevo token
            token = PasswordResetToken.objects.create(user=user)

            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = token.token
            reset_url = f"http://localhost:8000/reset-password/{uidb64}/{token}"
            send_mail(
                "Password Reset Request",
                f"Hi {user.username},\n\nPlease click on the link below to reset your password:\n\n{reset_url}",
                "ghost@comprala.co",
                [user.email],
                fail_silently=False,
            )
            return Response(
                {"message": "Hemos enviado un correo para restablecer tu contraseña."},
                status=status.HTTP_200_OK,
            )


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        if user:
            return Response(
                {"message": "Tu contraseña ha sido restablecida con éxito"},
                status=status.HTTP_200_OK,
            )

        else:
            return Response(
                {"error": "Error al intentar restablecer tu contraseña."},
                status=status.HTTP_400_BAD_REQUEST,
            )
