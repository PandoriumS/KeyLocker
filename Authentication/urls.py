from django.urls import path

from . import views


app_name = "Authentication"

urlpatterns = [
    path("register/", views.Register.as_view(), name="register"),
    path("login/", views.Login.as_view(), name="login"),
    path("confirm_registration/<str:token>", views.confirm_registration, name="confirm_user"),
    path("confirm_login/<str:token>", views.confirm_login, name="confirm_login"),
    path("logout/", views.logout_user, name="logout")
]
