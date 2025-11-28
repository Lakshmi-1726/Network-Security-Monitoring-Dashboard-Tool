from django.urls import path
from . import views


urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.user_login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.user_logout, name='logout'),
    path('api/events/', views.events_api, name='events_api'),
    path('api/events/export/', views.export_csv, name='export_csv'),
    path('api/events/stats/', views.events_stats, name='events_stats'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    path('api/collect-event/', views.collect_event, name='collect_event'),
    path('alerts/', views.alerts, name='alerts'),
    path("events/", views.events_list, name="events_list")

    
    

]
