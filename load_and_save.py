import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

def json_parser() -> dict:
    try:
        with open("settings.json", 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        
def _read_binary_file(file_path: str) -> bytes:
    """
    Вспомогательная функция для чтения бинарного файла
    """
    with open(file_path, 'rb') as file:
        return file.read()

def _write_binary_file(file_path: str, data: bytes) -> None:
    """
    Вспомогательная функция для записи в бинарный файл
    """
    with open(file_path, 'wb') as file:
        file.write(data)

def write_symmetric_key(symmetric_key: bytes, symmetric_path:str) -> None:
    """
    Сериализация симметричного ключа в файл
    """
    try:
        _write_binary_file(symmetric_path, symmetric_key)
    except Exception as ex:
        print(f"Ошибка!: {ex}")

def write_public_key(public_key: RSAPublicKey, public_path: str) -> None:
    """
    Сериализация открытого ключа в файл
    """
    try:
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        _write_binary_file(public_path, public_bytes)
    except Exception as ex:
        print(f"Ошибка!: {ex}")

def write_private_key(private_key: RSAPrivateKey, private_path: str) -> None:
    """
    Сериализация закрытого ключа в файл
    """
    try:
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        _write_binary_file(private_path, private_bytes)
    except Exception as ex:
        print(f"Ошибка!: {ex}")

def write_asymmetric_key(public_key: RSAPublicKey, private_key: RSAPrivateKey, public_path:str, private_path:str) -> None:
    """
    Сериализация асимметричных ключей в файл
    """
    write_public_key(public_key, public_path)
    write_private_key(private_key, private_path)

def read_symmetric_key(symmetric_key_path:str) -> bytes:
    """
    Чтение ключа из файла
    """
    try:
        return _read_binary_file(symmetric_key_path)
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return b""

def read_asymmetric_key(public_key_path:str, private_key_path) -> tuple:
    """
    Чтение RSA ключей из файлов
    """
    try:
        public_bytes = _read_binary_file(public_key_path)
        public_key = load_pem_public_key(public_bytes)
        
        private_bytes = _read_binary_file(private_key_path)
        private_key = load_pem_private_key(private_bytes, password=None)
        
        return public_key, private_key
    except Exception as ex:
        print(f"Ошибка!: {ex}")

def read_text(initial_file_path:str) -> bytes:
    """
    Чтение текста из файла
    """
    try:
        return _read_binary_file(initial_file_path)
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return b""
    
def write_text(text: bytes, enc_file_path: str) -> None:
    """
    Запись расшифрованного текста в файл
    """
    try:
        _write_binary_file(enc_file_path, text)
    except Exception as ex:
        print(f"Ошибка!: {ex}")
