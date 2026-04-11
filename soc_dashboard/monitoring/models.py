from django.db import models

class Event(models.Model):
    timestamp = models.TextField()
    event_type = models.TextField()
    source = models.TextField()
    message = models.TextField()
    severity = models.TextField()

    class Meta:
        managed = False   # IMPORTANT: Django will NOT manage the table
        db_table = "events"
