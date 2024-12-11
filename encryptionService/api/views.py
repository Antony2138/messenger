import json

import requests
from django.http import JsonResponse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
import os
import random
import base64
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from django.views import View
from .utils import (
    caesar_cipher_encrypt,
    aes_encrypt, generator, rsa_encrypt, generate_rsa_keys, caesar_cipher_decrypt, aes_decrypt, rsa_decrypt,
)

private_key = None
public_key = None
model = None
caesar_key = None
aes_key = None


@csrf_exempt
def generate_keys(request):
    global private_key, public_key, model, caesar_key, aes_key
    if request.method == 'POST':
        encryption_method = request.POST.get('method')

        if encryption_method == 'caesar':
            caesar_key = generator(encryption_method)
            return JsonResponse({
                'method': encryption_method,
                'status': "caesar_key generated successfully",
            })

        elif encryption_method == 'aes':
            # Генерация ключа для AES
            aes_key = generator(encryption_method)
            return JsonResponse({
                'method': encryption_method,
                'status': "aes_key generated successfully",
            })

        elif encryption_method == 'rsa':
            # Генерация ключей для DSA
            model, public_key, private_key = generate_rsa_keys()
            return JsonResponse({
                'method': encryption_method,
                'status': "rsa_key generated successfully",
            })

    else:
        return JsonResponse({'error': 'Unsupported encryption method'}, status=400)


@csrf_exempt
def send_public_key(request):
    global public_key, aes_key, caesar_key, model
    if request.method == 'POST':
        encryption_method = request.POST.get('method')
        data = {}
        if encryption_method == 'rsa':
            data['key'] = public_key
            data['model'] = model

        elif encryption_method == 'aes':
            data['key'] = base64.b64encode(aes_key).decode('utf-8')

        elif encryption_method == 'caesar':
            data['key'] = caesar_key

        # URL второго проекта (Receiver)
        receiver_url = 'http://localhost:8001/api/get_public_key/'

        data['encryption_method'] = encryption_method

        response = requests.post(receiver_url, json=data)
        return JsonResponse({
            'status1': 'Data sent',
            'response1': data,
            'receiver_response': response.json()
        })
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


@csrf_exempt
def get_public_key(request):
    global public_key, aes_key, caesar_key, model
    if request.method == 'POST':
        data = json.loads(request.body)
        if data.get('encryption_method') == 'caesar':
            caesar_key = data.get('key')
        elif data.get('encryption_method') == 'aes':
            aes_key = base64.b64decode(data.get('key'))
        elif data.get('encryption_method') == 'rsa':
            public_key = data.get('key')
            model = data.get('model')
        data['key'] = data.get('key')
        data['encryption_method'] = data.get('encryption_method')

        return JsonResponse({'status': 'Success', 'data': data})
    return JsonResponse({'error': 'Invalid request'}, status=400)


@csrf_exempt
def encrypt(request):
    global model, public_key, caesar_key, aes_key
    if request.method == 'POST':
        message = request.POST.get('message')
        method = request.POST.get('method')
        if method == 'rsa':
            if public_key:
                encrypted_message = rsa_encrypt(message, public_key, model)
                return JsonResponse({'encrypted_message': encrypted_message})
            else:
                return JsonResponse({'status': "you need key"})
        elif method == 'caesar':
            if caesar_key:
                encrypted_message = caesar_cipher_encrypt(message, caesar_key)
                return JsonResponse({'encrypted_message': encrypted_message})
            else:
                return JsonResponse({'status': "you need key?"})
        elif method == 'aes':
            if aes_key:
                encrypted_message = aes_encrypt(message, aes_key)
                return JsonResponse({'encrypted_message': encrypted_message})
            else:
                return JsonResponse({'status': "you need key"})
        else:
            return JsonResponse({'error': 'Unknown method'}, status=400)


@csrf_exempt
def encrypt_and_send(request):
    global model, public_key, caesar_key, aes_key
    if request.method == 'POST':
        message = request.POST.get('message')
        method = request.POST.get('method')
        receiver_url = 'http://localhost:8001/api/accept_msg/'
        data = {}
        if method == 'rsa':
            if not public_key:
                return JsonResponse({
                    'status': 'you need public key',
                })
            encrypted_message = rsa_encrypt(message, public_key, model)
            data['encrypted_message'] = encrypted_message
            response = requests.post(receiver_url, json=data)
            return JsonResponse({
                'status': 'Success',
                'encrypted_message': encrypted_message,
                'receiver_response': response.json()
            })
        if method == 'caesar':
            if not caesar_key:
                return JsonResponse({
                    'status': 'you need key',
                })
            encrypted_message = caesar_cipher_encrypt(message, caesar_key)
            data['encrypted_message'] = encrypted_message
            response = requests.post(receiver_url, json=data)
            return JsonResponse({
                'status': 'Success',
                'encrypted_message': encrypted_message,
                'receiver_response': response.json()
            })
        elif method == 'aes':
            if not aes_key:
                return JsonResponse({
                    'status': 'you need key',
                })
            encrypted_message = aes_encrypt(message, aes_key)
            data['encrypted_message'] = encrypted_message
            response = requests.post(receiver_url, json=data)
            return JsonResponse({
                'status': 'Success',
                'encrypted_message': encrypted_message,
                'receiver_response': response.json()
            })
        else:
            return JsonResponse({'error': 'Unknown method'}, status=400)


@csrf_exempt
def accept_msg(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        encrypted_message = data.get('encrypted_message')
        return JsonResponse({'encrypted_message': encrypted_message})


@csrf_exempt
def send_encrypted_msg(request):
    global model, public_key, caesar_key, aes_key
    if request.method == 'POST':
        message = request.POST.get('message')
        method = request.POST.get('method')
        receiver_url = 'http://localhost:8001/api/get_encrypted_msg/'
        data = {}
        data['message'] = message
        data['method'] = method
        print(message, "message", method, "method")
        if method == 'rsa':
            response = requests.post(receiver_url, json=data)
            return JsonResponse({
                'status': 'Success',
                'data': data,
                'receiver_response': response.json()
            })
        if method == 'caesar':
            response = requests.post(receiver_url, json=data)
            return JsonResponse({
                'status': 'Success',
                'data': data,
                'receiver_response': response.json()
            })
        elif method == 'aes':
            response = requests.post(receiver_url, json=data)
            return JsonResponse({
                'status': 'Success',
                'data': data,
                'receiver_response': response.json()
            })
        else:
            return JsonResponse({'error': 'Unknown method'}, status=400)


@csrf_exempt
def get_encrypted_msg(request):
    global model, caesar_key, aes_key, private_key
    if request.method == 'POST':
        data = json.loads(request.body)
        message = data.get('message')
        method = data.get('method')
        if method == 'rsa':
            if private_key:
                decrypted_message = rsa_decrypt(message, private_key, model)
                return JsonResponse({'decrypted_message': decrypted_message})
            else:
                return JsonResponse({'status': "you need private key "})

        if method == 'caesar':
            if caesar_key:
                decrypted_message = caesar_cipher_decrypt(message, caesar_key)
                return JsonResponse({'decrypted_message': decrypted_message})
            else:
                return JsonResponse({'status': "you need key "})

        elif method == 'aes':
            if aes_key:
                decrypted_message = aes_decrypt(message, aes_key)
                return JsonResponse({'decrypted_message': decrypted_message})
            else:
                return JsonResponse({'status': "you need key "})
        else:
            return JsonResponse({'error': 'Unknown method'}, status=400)

