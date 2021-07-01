'''
Алгоритм RSA с одноразовым ключом
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
Всем функциям на вход должны подаваться байты, а не строки!
'''

from typing import List, Optional
from types import MappingProxyType
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# размер padding'а(вроде)
SHA_SIZE = 256
# Валидный размеры закрытого ключа в БИТАХ
VALID_KEY_SIZES = (1024, 2048, 3072, 4096)
# Максимальный размер сообщения в БАЙТАХ, которое можно зашифровать за раз
MAX_SINGLE_MSG_SIZE = MappingProxyType({1024: 62, 2048: 190,
                                        3072: 318, 4096: 446})
# Размеры зашифрованого сообщения в БАЙТАХ. Зависят от размера закрытого ключа.
ENCRYPTED_SIZES = MappingProxyType({1024: 128, 2048: 256,
                                    3072: 384, 4096: 512})


def create_private_key(n_bits: int = 2048) -> rsa.RSAPrivateKey:
    '''
    Возвращает закрытый ключ для алгоритма RSA
    Допустимые значения n_bits: 1024, 2048, 3072, 4096.
    Чтобы получить открытый ключ, вызовите метод public_key объекта
    класса rsa.RSAPrivateKey.
    '''
    if n_bits not in VALID_KEY_SIZES:
        raise ValueError(f'Key must be in {VALID_KEY_SIZES}')
    return rsa.generate_private_key(public_exponent=65537, key_size=n_bits)


def save_private_key(filename: str,
                     private_key: rsa.RSAPrivateKey,
                     pswd_b: Optional[bytes] = None) -> None:
    '''
    Сохраняет закрытый ключ для алгоритма RSA в файл(.pem).
    Если pswd_b is None, то сохранение в файл происходит
    без шифрования.
    Если type(pswd_b) == type(bytes), то pswd_b -- байты
    пароля для шифрования файла.
    '''
    if pswd_b is None:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pswd_b)
        )
    if not filename.endswith('.pem'):
        filename = filename + '.pem'
    with open(filename, 'wb') as f:
        f.write(pem)


def save_public_key(filename: str, public_key: rsa.RSAPublicKey) -> None:
    '''
    Сохраняет открытый ключ для алгоритма RSA в файл(.pem).
    '''
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not filename.endswith('.pem'):
        filename = filename + '.pem'
    with open(filename, 'wb') as f:
        f.write(pem)


def load_private_key(filename: str,
                     pswd_b: Optional[bytes] = None
                     ) -> rsa.RSAPrivateKey:
    '''
    Загружает закрытый ключ из файла.
    Используйте pswd_b, если для расшифровки файла требуется пароль.
    '''
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=pswd_b,
        )
    return private_key


def load_public_key(filename: str) -> rsa.RSAPublicKey:
    '''Загружает из файла открытый ключ для RSA'''
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )
    return public_key


def encrypt(public_key: rsa.RSAPublicKey, msg_b: bytes) -> bytes:
    '''
    Шифрует байты msg_b, используя RSA алгоритм и открытый ключ.
    Максимальный размер сообщения -- 190 байт.
    '''
    if len(msg_b) > 190:
        raise ValueError(
            f'len(msg_b) = {len(msg_b)}. Длина обязана не превышать 190.'
        )
    ciphertext = public_key.encrypt(
        msg_b,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt(private_key: rsa.RSAPrivateKey, enc_b: bytes) -> bytes:
    '''
    Расшифровывает переданные байты enc_b, используя закрытый
    ключ и алгоритм RSA.
    '''
    plaintext = private_key.decrypt(
        enc_b,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def split_bytes(bstr: bytes, chunk_size=190):
    '''
    Разбивает байты на чанки размера chunk_size.
    Последний чанк может быть меньше других.
    Функция нужна для того, чтобы можно было шифровать
     сообщения любой длины.
    '''
    return [bytes[i: i + chunk_size]
            for i in range(0, len(bytes), chunk_size)]


def encrypt_long(public_key: rsa.RSAPublicKey, msg_b: bytes) -> bytes:
    '''
    Шифрует длинное сообщение.
    Разбивает сообщение на чанки размера
    MAX_SINGLE_MSG_SIZE[public_key.key_size], применяет к каждому
    чанку шифрование, потом конкатенирует зашифрованые чанки.
    '''
    chunks = split_bytes(msg_b, MAX_SINGLE_MSG_SIZE[public_key.key_size])
    enc_chunks = map(lambda x: encrypt(public_key, x), chunks)
    return b''.join(enc_chunks)


def decrypt_long(private_key: rsa.RSAPrivateKey, enc_b: bytes) -> bytes:
    '''
    Расшифровывает длинное сообщение.
    Разбивает сообщение на чанки размера
    ENCRYPTED_SIZES[private_key.key_size], применяет к каждому
    чанку дешифровку, потом конкатенирует расшифрованные чанки.
    '''
    chunks = split_bytes(enc_b, ENCRYPTED_SIZES[private_key.key_size])
    dec_chunks = map(lambda x: decrypt(private_key, x), chunks)
    return b''.join(dec_chunks)


def max_len(n_bits=2048):
    '''
    Максимальный размер сообщения, которое можно зашифровать за раз
    '''
    if n_bits not in VALID_KEY_SIZES:
        raise ValueError(f'Key must be in {VALID_KEY_SIZES}')
    return n_bits//8 - SHA_SIZE//4 - 2


if __name__ == '__main__':
    pr_k = create_private_key(3072)
    pu_k = pr_k.public_key()
