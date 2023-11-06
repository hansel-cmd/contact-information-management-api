from api.models import EmailConfirmationToken, ForgotPasswordToken
from django.utils import timezone

def main():
    make_email_code_expire()
    make_forgot_password_code_expire()
    

def make_forgot_password_code_expire():
    records = ForgotPasswordToken.objects.filter(will_expire_on__lt = timezone.now())
    records.update(is_expired = True)
    print(records)


def make_email_code_expire():
    records = EmailConfirmationToken.objects.filter(will_expire_on__lt = timezone.now())
    records.update(is_expired = True)
    print(records)

    # Also delete the user accounts that were not verified during the set duration.
    # Similar to google where the user account creation will not take effect if the OTP
    # is not provided.
    