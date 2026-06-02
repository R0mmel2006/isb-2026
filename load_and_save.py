import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def json_parser() -> dict:
    """
    Парсит JSON файл настроек и возвращает конфигурацию в виде словаря.
    
    Читает файл 'settings.json' из текущей директории и преобразует его
    содержимое в словарь Python для дальнейшего использования в приложении.
    
    Returns:
        dict: Словарь с настройками из файла settings.json.
        None: Возвращает None в случае ошибки чтения или парсинга файла.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с чтением файла или его содержимым.
    """
    try:
        with open("settings.json", 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return None


def _read_binary_file(file_path: str) -> bytes:
    """
    Вспомогательная функция для чтения бинарного файла.
    
    Открывает указанный файл в бинарном режиме и считывает всё его содержимое.
    
    Args:
        file_path (str): Путь к файлу для чтения.
    
    Returns:
        bytes: Содержимое файла в виде байтовой строки.
    
    Raises:
        FileNotFoundError: Если файл не существует.
        IOError: Если произошла ошибка при чтении файла.
    """
    with open(file_path, 'rb') as file:
        return file.read()


def _write_binary_file(file_path: str, data: bytes) -> None:
    """
    Вспомогательная функция для записи данных в бинарный файл.
    
    Открывает указанный файл в бинарном режиме для записи и записывает
    предоставленные данные. Если файл существует, он будет перезаписан.
    
    Args:
        file_path (str): Путь к файлу для записи.
        data (bytes): Байтовые данные для записи в файл.
    
    Raises:
        IOError: Если произошла ошибка при записи в файл.
        PermissionError: Если нет прав для записи в указанный файл.
    """
    with open(file_path, 'wb') as file:
        file.write(data)


def write_symmetric_key(symmetric_key: bytes, symmetric_path: str) -> None:
    """
    Сериализует и записывает симметричный ключ в файл.
    
    Сохраняет симметричный ключ (байтовую строку) в указанный файл
    в бинарном формате для дальнейшего использования.
    
    Args:
        symmetric_key (bytes): Симметричный ключ для сохранения.
        symmetric_path (str): Путь к файлу для сохранения ключа.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с записью файла.
    """
    try:
        _write_binary_file(symmetric_path, symmetric_key)
    except Exception as ex:
        print(f"Ошибка!: {ex}")


def write_public_key(public_key: RSAPublicKey, public_path: str) -> None:
    """
    Сериализует и записывает открытый RSA ключ в файл в формате PEM.
    
    Преобразует объект открытого ключа RSA в формат PEM (SubjectPublicKeyInfo)
    и сохраняет его в указанный файл.
    
    Args:
        public_key (RSAPublicKey): Объект открытого ключа RSA для сериализации.
        public_path (str): Путь к файлу для сохранения открытого ключа.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с сериализацией или записью файла.
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
    Сериализует и записывает закрытый RSA ключ в файл в формате PEM.
    
    Преобразует объект закрытого ключа RSA в формат PEM (TraditionalOpenSSL)
    без шифрования и сохраняет его в указанный файл.
    
    Args:
        private_key (RSAPrivateKey): Объект закрытого ключа RSA для сериализации.
        private_path (str): Путь к файлу для сохранения закрытого ключа.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с сериализацией или записью файла.
    
    Note:
        Закрытый ключ сохраняется без парольной защиты.
        Рекомендуется обеспечить безопасное хранение файла с закрытым ключом.
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


def write_asymmetric_key(public_key: RSAPublicKey, private_key: RSAPrivateKey, 
                         public_path: str, private_path: str) -> None:
    """
    Сериализует и записывает пару асимметричных RSA ключей в файлы.
    
    Сохраняет открытый и закрытый ключи RSA в отдельные файлы,
    вызывая соответствующие функции для каждого ключа.
    
    Args:
        public_key (RSAPublicKey): Объект открытого ключа RSA для сохранения.
        private_key (RSAPrivateKey): Объект закрытого ключа RSA для сохранения.
        public_path (str): Путь к файлу для сохранения открытого ключа.
        private_path (str): Путь к файлу для сохранения закрытого ключа.
    """
    write_public_key(public_key, public_path)
    write_private_key(private_key, private_path)


def read_symmetric_key(symmetric_key_path: str) -> bytes:
    """
    Читает симметричный ключ из файла.
    
    Загружает симметричный ключ из указанного файла в бинарном формате.
    
    Args:
        symmetric_key_path (str): Путь к файлу с симметричным ключом.
    
    Returns:
        bytes: Симметричный ключ в виде байтовой строки.
        b"": Пустая байтовая строка в случае ошибки чтения.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с чтением файла.
    """
    try:
        return _read_binary_file(symmetric_key_path)
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return b""


def read_asymmetric_key(public_key_path: str, private_key_path: str) -> tuple:
    """
    Читает пару асимметричных RSA ключей из файлов PEM формата.
    
    Загружает открытый и закрытый ключи RSA из указанных файлов,
    десериализуя их из PEM формата в объекты Python.
    
    Args:
        public_key_path (str): Путь к файлу с открытым ключом в формате PEM.
        private_key_path (str): Путь к файлу с закрытым ключом в формате PEM.
    
    Returns:
        tuple: Кортеж из двух элементов (public_key, private_key), где
               public_key - объект RSAPublicKey,
               private_key - объект RSAPrivateKey.
        None: Возвращает None в случае ошибки чтения или десериализации.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с чтением файлов или десериализацией ключей.
    """
    try:
        public_bytes = _read_binary_file(public_key_path)
        public_key = load_pem_public_key(public_bytes)
        
        private_bytes = _read_binary_file(private_key_path)
        private_key = load_pem_private_key(private_bytes, password=None)
        
        return public_key, private_key
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return None


def read_text(initial_file_path: str) -> bytes:
    """
    Читает текст или бинарные данные из файла.
    
    Загружает содержимое файла в бинарном формате для последующей
    обработки (шифрования, дешифрования и т.д.).
    
    Args:
        initial_file_path (str): Путь к файлу для чтения.
    
    Returns:
        bytes: Содержимое файла в виде байтовой строки.
        b"": Пустая байтовая строка в случае ошибки чтения.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с чтением файла.
    """
    try:
        return _read_binary_file(initial_file_path)
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return b""


def write_text(text: bytes, enc_file_path: str) -> None:
    """
    Записывает текст или бинарные данные в файл.
    
    Сохраняет байтовые данные (зашифрованные или расшифрованные)
    в указанный файл.
    
    Args:
        text (bytes): Байтовые данные для записи в файл.
        enc_file_path (str): Путь к файлу для сохранения данных.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с записью файла.
    """
    try:
        _write_binary_file(enc_file_path, text)
    except Exception as ex:
        print(f"Ошибка!: {ex}")
