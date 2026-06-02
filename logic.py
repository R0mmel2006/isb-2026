from load_and_save import (write_asymmetric_key, write_symmetric_key, write_text,
                           read_asymmetric_key, read_symmetric_key, read_text)
from symmetric import get_symmetric_key, encrypt_text, decrypt_text
from asymmetric import encrypt_symmetric_key, decrypt_symmetric_key, get_asymmetric_key


def gen_logic(settings: dict, key_length: int) -> tuple:
    """
    Выполняет процесс генерации криптографических ключей.
    
    Создает симметричный ключ для алгоритма 3DES и пару асимметричных 
    RSA ключей. Симметричный ключ шифруется открытым RSA ключом и 
    сохраняется вместе с асимметричными ключами.
    
    Args:
        settings (dict): Словарь с настройками, содержащий пути для 
                        сохранения ключей:
                        - symmetric_key_path: путь для зашифрованного симметричного ключа
                        - public_key_path: путь для открытого RSA ключа
                        - private_key_path: путь для закрытого RSA ключа
        key_length (int): Длина симметричного ключа в битах (64, 128 или 192).
                         Внутренне преобразуется в байты (делением на 8).
    
    Returns:
        tuple: Кортеж из трех элементов (symmetric_key, public_key, private_key), где:
               - symmetric_key (bytes): сгенерированный симметричный ключ,
               - public_key (RSAPublicKey): сгенерированный открытый RSA ключ,
               - private_key (RSAPrivateKey): сгенерированный закрытый RSA ключ.
    
    Raises:
        Exception: Может возникнуть ошибка при генерации ключей или 
                   записи их в файлы.
    """
    symmetric_key = get_symmetric_key(key_length // 8)
    private_key, public_key = get_asymmetric_key()
    encrypted_key = encrypt_symmetric_key(symmetric_key, public_key)
    write_symmetric_key(encrypted_key, settings["symmetric_key_path"])
    write_asymmetric_key(public_key, private_key, 
                        settings["public_key_path"], 
                        settings["private_key_path"])
    print("Ключи успешно сгенерированы")
    return symmetric_key, public_key, private_key


def enc_logic(settings: dict, initial_file_path: str, encrypted_file_path: str) -> tuple:
    """
    Выполняет процесс шифрования текста.
    
    Загружает симметричный и асимметричные ключи из файлов, расшифровывает
    симметричный ключ с помощью закрытого RSA ключа, читает исходный текст,
    шифрует его с помощью алгоритма 3DES и сохраняет зашифрованный результат.
    
    Args:
        settings (dict): Словарь с настройками, содержащий пути к ключам:
                        - symmetric_key_path: путь к зашифрованному симметричному ключу
                        - public_key_path: путь к открытому RSA ключу
                        - private_key_path: путь к закрытому RSA ключу
        initial_file_path (str): Путь к исходному файлу с текстом для шифрования.
        encrypted_file_path (str): Путь для сохранения зашифрованного текста.
    
    Returns:
        tuple: Кортеж из двух элементов (enc_text, symmetric_key), где:
               - enc_text (bytes): зашифрованный текст,
               - symmetric_key (bytes): расшифрованный симметричный ключ.
    
    Raises:
        Exception: Может возникнуть ошибка при чтении ключей, 
                   расшифровке симметричного ключа или шифровании текста.
    """
    symmetric_key = read_symmetric_key(settings["symmetric_key_path"])
    public_key, private_key = read_asymmetric_key(settings["public_key_path"], 
                                                  settings["private_key_path"])
    symmetric_key = decrypt_symmetric_key(symmetric_key, private_key)
    text = read_text(initial_file_path)
    enc_text = encrypt_text(text, symmetric_key)
    write_text(enc_text, encrypted_file_path)
    print("Текст успешно зашифрован")
    return enc_text, symmetric_key
    

def dec_logic(settings: dict, encrypted_file_path: str, decrypted_file_path: str) -> tuple:
    """
    Выполняет процесс дешифрации текста.
    
    Загружает симметричный и асимметричные ключи из файлов, расшифровывает
    симметричный ключ с помощью закрытого RSA ключа, читает зашифрованный текст,
    расшифровывает его с помощью алгоритма 3DES и сохраняет расшифрованный результат.
    
    Args:
        settings (dict): Словарь с настройками, содержащий пути к ключам:
                        - symmetric_key_path: путь к зашифрованному симметричному ключу
                        - public_key_path: путь к открытому RSA ключу
                        - private_key_path: путь к закрытому RSA ключу
        encrypted_file_path (str): Путь к файлу с зашифрованным текстом.
        decrypted_file_path (str): Путь для сохранения расшифрованного текста.
    
    Returns:
        tuple: Кортеж из двух элементов (text, symmetric_key), где:
               - text (bytes): расшифрованный текст,
               - symmetric_key (bytes): расшифрованный симметричный ключ.
    
    Raises:
        Exception: Может возникнуть ошибка при чтении ключей, 
                   расшифровке симметричного ключа или дешифровании текста.
    """
    symmetric_key = read_symmetric_key(settings["symmetric_key_path"])
    public_key, private_key = read_asymmetric_key(settings["public_key_path"], 
                                                  settings["private_key_path"])
    symmetric_key = decrypt_symmetric_key(symmetric_key, private_key)
    text = read_text(encrypted_file_path)
    text = decrypt_text(text, symmetric_key)
    write_text(text, decrypted_file_path)
    print("Текст успешно расшифрован")
    return text, symmetric_key
