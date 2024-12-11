from django.urls import path
from .views import send_public_key, get_public_key, generate_keys, accept_msg, encrypt_and_send, encrypt, \
    get_encrypted_msg, send_encrypted_msg

urlpatterns = [
    path('encrypt/', encrypt, name='encrypt'),
    path('encrypt_and_send/', encrypt_and_send, name='encrypt'),
    path('send_encrypted_msg/', send_encrypted_msg, name='send_encrypted_msg'),
    path('get_encrypted_msg/', get_encrypted_msg, name='get_encrypted_msg'),
    path('generate/', generate_keys, name='generate_keys'),
    path('send_public_key/', send_public_key, name='generate_keys'),
    path('get_public_key/', get_public_key, name='generate_keys'),
    path('accept_msg/', accept_msg, name='accept_msg'),

]