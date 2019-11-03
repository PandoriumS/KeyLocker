from django.db import models
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist

from skimage.io import imread, imsave


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, verbose_name=_("User"))
    avatar = models.ImageField(upload_to="avatars", verbose_name=_("Avatar"), default="default_avatar.png")

    class Meta:
        verbose_name = _("User Profile")
        verbose_name_plural = _("User Profiles")

    def save(self, *args, **kwargs):
        try:
            this = Profile.objects.get(id=self.id)
            if this.avatar != self.avatar:
                avatar_name = self.avatar.name.split('.')
                avatar_name[0] = f"{self.user.username.capitalize()}'s Avatar"
                self.avatar.name = '.'.join(avatar_name)
                this.avatar.delete(save=False)
        except ObjectDoesNotExist:
            pass

        super().save(*args, **kwargs)

        img = imread(self.avatar.path)
        if img.shape[0] != img.shape[1]:
            if img.shape[0] > img.shape[1]:
                half = (img.shape[0] - img.shape[1]) // 2
                new_img = img[half: -half, :]
            else:
                half = (img.shape[1] - img.shape[0]) // 2
                new_img = img[:, half: -half]
            imsave(img_path, new_img)
