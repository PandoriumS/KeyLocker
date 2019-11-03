from django import forms


class MessageForm(forms.Form):
    email = forms.CharField(widget=forms.TextInput)
    text = forms.CharField(widget=forms.Textarea)

    email.widget.attrs.update({
        "id": "test-email-input",
        "class": "test-form-field",
        "placeholder": "Email Address..",
        "autofocus": True
    })

    text.widget.attrs.update({
        "id": "test-text-input",
        "class": "test-form-field",
        "placeholder": "Text.."
    })