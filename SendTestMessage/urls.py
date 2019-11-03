from django.urls import path
from . import views


app_name = "SendMail"

urlpatterns = [
    path('', views.SendMessageView.as_view(), name="send_message")
]