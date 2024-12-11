from django.urls import path
from .views import encrypt, generate_keys, send_public_key, get_public_key, encrypt_and_send, accept_msg, \
    send_encrypted_msg, get_encrypted_msg

urlpatterns = [
    path('encrypt/', encrypt, name='encrypt'),
    path('encrypt_and_send/', encrypt_and_send, name='encrypt_and_send'),
    path('generate/', generate_keys, name='generate'),
    path('send_encrypted_msg/', send_encrypted_msg, name='send_encrypted_msg'),
    path('get_encrypted_msg/', get_encrypted_msg, name='get_encrypted_msg'),
    path('send_public_key/', send_public_key, name='send_public_key'),
    path('get_public_key/', get_public_key, name='get_public_key'),
    path('accept_msg/', accept_msg, name='accept_msg'),

]
