from django.contrib import admin
from .models import CompralaUser, PasswordResetToken, EmailVerificationToken


class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "username", "email", "is_verified")
    search_fields = ("username", "email")
    list_per_page = 25


class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "token", "created_at")
    search_fields = ("user", "token")
    list_per_page = 25


class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "token", "created_at")
    search_fields = ("user", "token")
    list_per_page = 25


admin.site.register(CompralaUser, UserAdmin)
admin.site.register(PasswordResetToken, PasswordResetTokenAdmin)
admin.site.register(EmailVerificationToken, EmailVerificationTokenAdmin)
