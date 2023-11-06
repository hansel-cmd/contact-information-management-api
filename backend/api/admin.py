from django.contrib import admin
from .models import User, Contact, EmailConfirmationToken, ForgotPasswordToken

# Register your models here.
admin.site.register(User)
admin.site.register(Contact)

@admin.register(EmailConfirmationToken)
class EmailConfirmationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'is_expired', 'will_expire_on', 'created_at', 'updated_at')

@admin.register(ForgotPasswordToken)
class ForgotPasswordTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'is_expired', 'will_expire_on', 'created_at', 'updated_at')