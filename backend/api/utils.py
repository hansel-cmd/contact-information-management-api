from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags


def send_confirmation_email(email, user_id, token):
    data = { 'token': token }
    html_message = render_to_string('api/confirmation_email.html', context = data)
    plain_message = strip_tags(html_message)
    print("email confirmation was sent!")

    send_mail(subject = 'Email Confirmation Code', 
            from_email='no-reply@contact-ease.com',
            recipient_list=[email],
            fail_silently=False,
            message=plain_message,
            html_message=html_message,
            connection=None,
            )
