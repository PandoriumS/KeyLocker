from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render, redirect, reverse
from django.utils.translation import ugettext_lazy as _
from django.views import View

from .forms import RegistrationForm, LoginForm
from .models import Profile

import jwt
import time
import random


class Register(View):
    template_name = "Authentication/register.html"
    form_class = RegistrationForm

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("")
        print(request.user)
        form = self.form_class()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = self.form_class(request.POST, request.FILES)
        if form.is_valid():
            cleaned_data = form.clean()
            username = cleaned_data["username"]
            email = cleaned_data["email"]
            password = cleaned_data["password"]

            try:
                if User.objects.get(username=username):
                    messages.error(request, _("User with the same username already exists! Try another username."))
                    return redirect("Authentication:register")
                elif User.objects.get(email=email):
                    messages.error(request, _("User with the same email already exists! Try another username."))
                    return redirect("Authentication:register")
            except ObjectDoesNotExist:
                pass

            user = User(username=username, email=email)
            user.set_password(password)
            user.is_active = False
            user.save()
            profile = Profile(user=user)
            if cleaned_data["avatar"]:
                profile.avatar = cleaned_data["avatar"]
            profile.save()
            message = _("You need to activate your account.")
            messages.info(request, message)
            return redirect("Authentication:login")
        messages.error(request, form.errors)
        return render(request, self.template_name, {"form": form})


def confirm_registration(request, token):
    print(request.session.items())
    token_binary = token.encode("utf-8")
    try:
        token_info = jwt.decode(token_binary, request.session["secret_message"], algorithms=["HS256"])
        print(f"token_info: {token_info}")
    except jwt.InvalidSignatureError:
        messages.error(request, _("You need to enter from the same browser!"))
        return redirect("Authentication:login")
    else:
        first_key = request.session["key"]
        second_key = token_info[first_key]
        key = list()
        for i in range(max(len(first_key), len(second_key))):
            try:
                key.extend([first_key[i], second_key[i]])
            except IndexError:
                try:
                    key.append(first_key[i])
                except IndexError:
                    key.append(second_key[i])
        key = "".join(key)
        secret_message = list()
        message = request.session["message"]
        for i in range(len(key)):
            secret_message.append(chr(ord(message[i]) ^ ord(key[i])))
        print(secret_message)
        print(request.session.get("secret"))
        print(request.session.get("secret_message"))
        if "".join(secret_message) == request.session.get("secret_message"):
            user = User.objects.get(username=token_info["user"]["username"])
            user.is_active = True
            user.save()
            login(request, authenticate(username=user.username, password=token_info["user"]["password"]))
            return render(request, "Authentication/confirm_user.html")
        else:
            messages.info(request, _("Something goes wrong :c Try again!"))
            return redirect("Authentication:login")




def confirm_login(request, token):
    token_binary = token.encode()


class Login(View):
    template_name = "Authentication/login.html"
    form_class = LoginForm

    def __confirm_registration(self, request, user):
        info: dict = self.__generate_secret_message()
        key: str = info["key"]
        request.session.set_expiry(310)
        request.session["message"] = info["message"]
        request.session["key"] = key[::2]
        request.session["secret_message"] = info["secret_message"]
        key = key[1::2]
        token: bytes = jwt.encode({request.session["key"]: key, "user": user, "exp": time.time() + 300},
                                  info["secret_message"],
                                  algorithm="HS256")
        message: str = _("""
            Hello, {}! You are trying to confirm your registration in Safe Room!
            If it is true, go to this page: {}. Else, skip this message.
            The url will become invalid in five minutes. 
        """.format(user["username"], reverse("Authentication:confirm_user", kwargs={"token": token.decode("utf-8")})))
        send_mail(_("Confirm your account"), message, settings.EMAIL_HOST_USER, [user["email"]], fail_silently=False,
                  auth_user=settings.EMAIL_HOST_USER, auth_password=settings.EMAIL_HOST_PASSWORD)
        print(token)
        return token

    def __confirm_login(self, request):
        pass

    @staticmethod
    def __generate_secret_message() -> dict():
        message_bytes = bytearray(list(range(256)))
        key_bytes = bytearray(list(range(256)))
        random.shuffle(message_bytes)
        random.shuffle(key_bytes)
        message = list()
        key = list()
        secret_message = list()
        for i in range(32):
            message.append(random.choice(message_bytes))
            key.append(random.choice(key_bytes))
            message_bytes.remove(message[-1])
            key_bytes.remove(key[-1])
            secret_message.append(message[-1] ^ key[-1])
        del message_bytes
        del key_bytes
        return {
            "message": ''.join([chr(x) for x in message]),
            "key": ''.join([chr(x) for x in key]),
            "secret_message": ''.join([chr(x) for x in secret_message])
        }

    def get(self, request):
        print(request.session.items())
        if request.user.is_authenticated:
            return redirect("")
        form = self.form_class()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            cleaned_data = form.clean()
            username = cleaned_data["username"]
            password = cleaned_data["password"]
            try:
                user = User.objects.get(username=username)
                if not user.check_password(password):
                    raise ObjectDoesNotExist
            except ObjectDoesNotExist:
                user = None
            if user is not None:
                if user.is_active:
                    self.__confirm_login(request)
                    return redirect("Authentication:confirm_login")
                else:
                    user_info = {
                        "username": username,
                        "email": user.email,
                        "password": password
                    }
                    self.__confirm_registration(request, user_info)
                    return render(request, "Authentication/confirm_user_timer_page.html")
            else:
                message = _("Incorrect username or password. Try again!")
                messages.error(request, message)
                return redirect("Authentication:login")


@login_required(redirect_field_name="/auth/register/")
def logout_user(request):
    pass

