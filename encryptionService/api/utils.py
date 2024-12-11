import os
import random
import base64
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import random
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import random
from gmpy2 import is_prime, mpz
from sympy import isprime


def caesar_cipher_encrypt(message, shift):
    encrypted = ""
    for char in message:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted


def caesar_cipher_decrypt(encrypted_message, shift):
    return caesar_cipher_encrypt(encrypted_message, -shift)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def aes_encrypt(message, key):
    # Преобразование сообщения в байты
    message_bytes = message.encode('utf-8')
    encrypted = bytearray(len(message_bytes))

    # Шифрование с использованием XOR
    for i in range(len(message_bytes)):
        encrypted[i] = message_bytes[i] ^ key[i % len(key)]

    # Кодирование в Base64
    return base64.b64encode(encrypted).decode('utf-8')


def aes_decrypt(encrypted_message, key):
    # Декодирование из Base64
    decoded = base64.b64decode(encrypted_message)
    decrypted = bytearray(len(decoded))

    # Дешифрование с использованием XOR
    for i in range(len(decoded)):
        decrypted[i] = decoded[i] ^ key[i % len(key)]

    return decrypted.decode('utf-8')


def rsa_encrypt(message, public_key, modulus):
    # Преобразование сообщения в целое число
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')

    # Проверка, что сообщение не превышает модуль
    if message_int >= modulus:
        raise ValueError("Message is too large for the current modulus.")

    # Шифрование сообщения с использованием RSA
    encrypted = pow(message_int, public_key, modulus)

    return encrypted


def rsa_decrypt(encrypted_message, private_key, modulus):
    encrypted_int = int(encrypted_message)
    decrypted_int = pow(encrypted_int, private_key, modulus)
    decrypted_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big').decode('utf-8',
                                                                                                              errors='ignore')
    return decrypted_message


#Generator
############################################################
def generator(encryption_method):
    if encryption_method == 'caesar':
        # Простой шифр Цезаря: ключ - смещение
        key = random.randint(3, 20)  # Можно сделать динамическим
        return key

    elif encryption_method == 'aes':
        # Генерация ключа для AES
        key = os.urandom(16)  # 128-битный ключ
        return key
############################################################
def generate_prime_candidate(length):
    """Генерация кандидата в простые числа заданной длины"""
    p = random.getrandbits(length)
    # Убедимся, что p нечетное
    p |= (1 << length - 1) | 1
    return p


def generate_prime(length):
    """Генерация простого числа заданной длины"""
    p = 4  # Начальное значение, чтобы войти в цикл
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p


def generate_rsa_keys(bit_length=1024):
    # Генерация двух простых чисел p и q
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)

    # Вычисление модуля n
    modulus = p * q

    # Вычисление функции Эйлера φ(n)
    phi = (p - 1) * (q - 1)

    # Генерация открытого ключа e
    while True:
        public_key = random.randrange(2, phi)
        if gcd(public_key, phi) == 1:
            break

    # Генерация закрытого ключа d
    private_key = mod_inverse(public_key, phi)

    return modulus, public_key, private_key


def gcd(a, b):
    """Вычисление наибольшего общего делителя (НОД)"""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    """Вычисление обратного элемента a по модулю m с использованием расширенного алгоритма Евклида"""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        # q - Частное
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

