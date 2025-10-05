from django.db import models


class TimestampModel(models.Model):
    """
    common fields for all model
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
