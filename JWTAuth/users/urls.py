from django.urls import path, include
from knox import views as knox_views
from .views import *

app_name = 'users'  # Add this line to set the app name

urlpatterns = [
    path('allUsers/', UserListView.as_view(), name='abc'),
    path('register/', CreateNewUser.as_view(), name='register'),
    path('login/', Login.as_view(), name='login'),
    path('logout/', Logout.as_view(), name='logout'),
    path('logoutall/', LogoutAllUsersView.as_view(), name='logout2'),
    



]
