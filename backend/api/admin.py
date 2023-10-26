from django.contrib import admin
from .models import User, Contact, EmailConfirmationToken

# Register your models here.
admin.site.register(User)
admin.site.register(Contact)
admin.site.register(EmailConfirmationToken)