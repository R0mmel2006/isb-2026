import os
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_symmetric_key(byt: int) -> bytes:
    """
    Генерирует криптографически стойкий симметричный ключ.
    
    Использует os.urandom() для создания случайных байтов,
    подходящих для использования в качестве ключа симметричного шифрования.
    
    Args:
        byt (int): Длина ключа в байтах.
                  Для 3DES допустимые значения: 8 (64 бита), 
                  16 (128 бит), 24 (192 бита).
    
    Returns:
        bytes: Случайный симметричный ключ указанной длины.
    
    Example:
        >>> key = get_symmetric_key(24)  # Ключ длиной 192 бита (24 байта)
        >>> len(key)
        24
    """
    key = os.urandom(byt)
    return key


def padding_text(text: bytes) -> bytes:
    """
    Добавляет паддинг к тексту согласно стандарту ANSI X.923.
    
    Приводит длину текста к кратности размеру блока алгоритма 3DES
    (8 байт = 64 бита) путем добавления специальных байтов паддинга.
    
    Args:
        text (bytes): Исходный текст для добавления паддинга.
    
    Returns:
        bytes: Текст с добавленным паддингом, длина которого кратна 8 байтам.
    
    Note:
        Используется стандарт ANSI X.923, при котором все байты паддинга,
        кроме последнего, равны 0x00, а последний байт содержит количество
        добавленных байтов.
    """
    padder = sym_padding.ANSIX923(64).padder()
    padded_text = padder.update(text) + padder.finalize()
    return padded_text


def encrypt_text(text: bytes, symmetric_key: bytes) -> bytes:
    """
    Шифрует текст с помощью алгоритма 3DES в режиме CBC.
    
    Добавляет паддинг к тексту, генерирует случайный вектор инициализации (IV)
    и выполняет шифрование. Возвращает IV вместе с зашифрованными данными
    для возможности последующего дешифрования.
    
    Args:
        text (bytes): Исходный текст для шифрования.
        symmetric_key (bytes): Симметричный ключ для алгоритма 3DES.
                              Должен быть длиной 8, 16 или 24 байта.
    
    Returns:
        bytes: Зашифрованные данные в формате: IV (8 байт) + зашифрованный текст.
              IV необходим для дешифрования и хранится в начале результата.
    
    Raises:
        ValueError: Если длина ключа не подходит для 3DES.
        Exception: Если произошла ошибка в процессе шифрования.
    
    Note:
        Режим CBC (Cipher Block Chaining) обеспечивает лучшую безопасность
        по сравнению с режимом ECB, так как каждый блок шифротекста зависит
        от всех предыдущих блоков.
    """
    iv = os.urandom(8)  # Вектор инициализации для режима CBC (8 байт)
    cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_text = padding_text(text)
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return iv + encrypted_text


def decrypt_text(encrypted_data: bytes, symmetric_key: bytes) -> bytes:
    """
    Дешифрует текст с помощью алгоритма 3DES в режиме CBC и удаляет паддинг.
    
    Извлекает вектор инициализации (IV) из начала зашифрованных данных,
    выполняет дешифрование и удаляет паддинг согласно стандарту ANSI X.923.
    
    Args:
        encrypted_data (bytes): Зашифрованные данные в формате: 
                               IV (8 байт) + зашифрованный текст.
        symmetric_key (bytes): Симметричный ключ для алгоритма 3DES.
                              Должен быть длиной 8, 16 или 24 байта.
    
    Returns:
        bytes: Расшифрованный текст без паддинга.
        b"": Пустая байтовая строка в случае ошибки дешифрования.
    
    Raises:
        Exception: Выводит сообщение об ошибке в консоль при проблемах
                   с дешифрованием или удалением паддинга.
    
    Note:
        Функция автоматически извлекает IV из первых 8 байт входных данных.
        Если паддинг некорректен (например, данные были повреждены),
        функция вернет пустую байтовую строку.
    """
    try:
        iv = encrypted_data[:8]  # Извлекаем IV из первых 8 байт
        ciphertext = encrypted_data[8:]  # Остальные данные - зашифрованный текст
        cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.ANSIX923(64).unpadder()
        unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        return unpadded_text
    except Exception as ex:
        print(f"Ошибка!: {ex}")
        return b""
