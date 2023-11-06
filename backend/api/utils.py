from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags


def send_confirmation_email(email, user_id, token, service):
    data = { 'token': token }
    html_message = ''
    subject = ''
    if service == 'email verification':
        html_message = render_to_string('api/confirmation_email.html', context = data)
        subject = 'Email Confirmation Code'
    elif service == 'forgot password':
        html_message = render_to_string('api/reset_password_email.html', context = data)
        subject = 'Reset Password Code'
    else:
        raise Exception("Incorrect service type.")
    
    plain_message = strip_tags(html_message)
    print("cnfirmation code was sent to your email!")

    send_mail(subject = subject, 
            from_email='no-reply@synk.com',
            recipient_list=[email],
            fail_silently=False,
            message=plain_message,
            html_message=html_message,
            connection=None,
            )
