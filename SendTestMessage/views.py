from django.shortcuts import render, redirect
from django.views import View
from django.contrib import messages
from django.conf import settings
from django.core.mail import send_mail

from .forms import MessageForm


class SendMessageView(View):
    template = "SendTestMessage/index.html"
    form = MessageForm

    def get(self, request):
        form = self.form()
        return render(request, self.template, {"form": form})

    def post(self, request):
        form = self.form(request.POST)
        if form.is_valid():
            email_addr = form.cleaned_data["email"]
            text = form.cleaned_data["text"]
            send_mail("Some subject", text, settings.EMAIL_HOST_USER, [email_addr], fail_silently=False)
            messages.info(request, "Sent message")
            return redirect("SendMail:send_message")
        else:
            messages.error("Invalid input")
            return redirect("SendMail:send_message")
