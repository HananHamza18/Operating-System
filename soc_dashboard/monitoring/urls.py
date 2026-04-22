from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("auth/", views.auth_events, name="auth_events"),
    path("processes/", views.process_events, name="process_events"),
    path("filesystem/", views.filesystem_events, name="filesystem_events"),
    path("timeline/", views.timeline, name="timeline"),
]
