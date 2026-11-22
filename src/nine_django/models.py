from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class NineIdentity(models.Model):
    """Links a 9in user (``iss`` + ``sub``) to a local Django user.

    Created on the first sign-in through ``/nine/callback``. A user can have several, for
    example one from your tenant's sandbox and one from production.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="nine_identities",
        verbose_name=_("user"),
    )
    issuer = models.CharField(_("issuer"), max_length=255)
    sub = models.CharField(_("9in user id"), max_length=255, help_text=_("The sub claim, e.g. usr_…"))
    created_at = models.DateTimeField(_("linked at"), auto_now_add=True)
    last_login_at = models.DateTimeField(_("last 9in sign-in"), null=True, blank=True)

    class Meta:
        verbose_name = _("9in identity")
        verbose_name_plural = _("9in identities")
        constraints = [models.UniqueConstraint(fields=["issuer", "sub"], name="nine_identity_issuer_sub")]
        indexes = [models.Index(fields=["sub"], name="nine_identity_sub")]

    def __str__(self) -> str:
        return f"{self.sub} ({self.issuer})"
