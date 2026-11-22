from django.apps import AppConfig


class NineConfig(AppConfig):
    name = "nine_django"
    label = "nine_django"
    verbose_name = "9in"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.core.signals import setting_changed

        from . import checks  # noqa: F401  (registers the system checks)
        from .services import reset

        def on_setting_changed(setting: str, **kwargs: object) -> None:
            if setting in ("NINE", "CACHES", "AUTH_USER_MODEL"):
                reset()

        setting_changed.connect(on_setting_changed, dispatch_uid="nine_django.reset", weak=False)
