from django.shortcuts import render

def confirm_password(request, uidb64, token):
    context = {
        'uid': uidb64,
        'token': token,
    }
    return render(request, 'account/passwords/password-reset.html', context)

def verify_email(request, key, email):
    context = {
        'key': key,
        'email': email,
    }
    return render(request, 'account/emails/email-confirm.html', context)
