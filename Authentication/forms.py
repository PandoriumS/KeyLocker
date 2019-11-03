from django import forms
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _


class RegistrationForm(forms.ModelForm):
    avatar = forms.ImageField(required=False, widget=forms.FileInput())
    check_password = forms.CharField(label=_("Repeat Password"), widget=forms.PasswordInput())

    avatar.widget.attrs.update({
        "id": "avatar-field",
    })

    check_password.widget.attrs.update({
        "id": "check-password-field",
        "class": "auth-field",
        "autocomplete": "off",
        "placeholder": _("Repeat Password")
    })

    class Meta:
        model = User
        fields = ("username", "email", "password")
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "id": "username-field",
                    "class": "auth-field",
                    "autocomplete": "off",
                    "spellcheck": "false",
                    "autofocus": True,
                    "placeholder": _("Username")
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "id": "email-field",
                    "class": "auth-field",
                    "autocomplete": "off",
                    "placeholder": _("Email")
                }
            ),
            "password": forms.PasswordInput(
                attrs={
                    "id": "password-field",
                    "class": "auth-field",
                    "autocomplete": "off",
                    "placeholder": _("Password")
                }
            )
        }

        labels = {
            "username": "Username",
            "email": "Email",
            "password": _("Password")
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data["password"]
        check_password = cleaned_data["check_password"]
        if password != check_password:
            raise forms.ValidationError(_("Passwords do not match"))
        return cleaned_data


class LoginForm(forms.Form):
    username = forms.CharField(label="Username", max_length=150, widget=forms.TextInput())
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput())

    username.widget.attrs.update({
        "id": "username-field",
        "class": "auth-field",
        "autocomplete": "off",
        "autofocus": True,
        "spellcheck": "false"
    })

    password.widget.attrs.update({
        "id": "password-field",
        "class": "auth-field",
        "autocomplete": "off",
    })


