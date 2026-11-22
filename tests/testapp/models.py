from django.db import models


class Profile(models.Model):
    """A related model, for adapter field paths like profile__phone."""

    user = models.OneToOneField("auth.User", on_delete=models.CASCADE, related_name="profile")
    phone = models.CharField(max_length=32, blank=True, default="")
    email_confirmed = models.BooleanField(default=False)
