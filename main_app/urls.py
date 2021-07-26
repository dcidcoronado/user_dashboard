from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('logoff', views.logoff),
    path('signin', views.signin),
    path('post_signin', views.signin),
    path('register', views.register),
    path('post_register', views.register),
    path('dashboard', views.dashboard),
    path('post_new', views.new_user),
    path('users/new', views.new_user),
    path('users/show/<user_id>', views.show_user),
    path('users/show/<user_id>/post_message', views.show_user),
    path('users/show/<user_id>/post_comment', views.post_comment),
    path('users/edit', views.edit_user),
    path('users/edit_user', views.edit_user),
    path('users/edit_description', views.edit_description),
    path('users/edit_password', views.edit_password),
    path('users/edit/<user_id>/edit_user', views.admin_edit),
    path('users/edit/<user_id>', views.admin_edit),
    path('users/edit/<user_id>/edit_password', views.admin_edit_password),
    path('users/remove/<user_id>', views.remove),
]
