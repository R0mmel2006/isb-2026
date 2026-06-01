from load_and_save import write_asymmetric_key, write_symmetric_key, write_text, read_asymmetric_key, read_symmetric_key,  read_text
from symmetric import get_symmetric_key, encrypt_text, decrypt_text
from asymmetric import encrypt_symmetric_key, decrypt_symmetric_key, get_asymmetric_key

def gen_logic(settings:dict, key_length) -> tuple:
    """
    Процесс генерации ключей
    """
    symmetric_key = get_symmetric_key(key_length // 8)
    private_key, public_key = get_asymmetric_key()
    encrypted_key = encrypt_symmetric_key(symmetric_key, public_key)
    write_symmetric_key(encrypted_key, settings["symmetric_key_path"])
    write_asymmetric_key(public_key, private_key, settings["public_key_path"], settings["private_key_path"])
    print("Ключи успешно сгенерированы")
    return symmetric_key, public_key, private_key

def enc_logic(settings: dict, initial_file_path, encrypted_file_path) -> tuple:
    """
    Процесс шифрования текста
    """
    symmetric_key = read_symmetric_key(settings["symmetric_key_path"])
    public_key, private_key = read_asymmetric_key(settings["public_key_path"], settings["private_key_path"])
    symmetric_key = decrypt_symmetric_key(symmetric_key, private_key)
    text = read_text(initial_file_path)
    enc_text = encrypt_text(text, symmetric_key)
    write_text(enc_text, encrypted_file_path)
    print("Текст успешно зашифрован")
    return enc_text, symmetric_key
    

def dec_logic(settings: dict, encrypted_file_path, decrypted_file_path):
    """
    Процесс дешифрации текста
    """
    symmetric_key = read_symmetric_key(settings["symmetric_key_path"])
    public_key, private_key = read_asymmetric_key(settings["public_key_path"], settings["private_key_path"])
    symmetric_key = decrypt_symmetric_key(symmetric_key, private_key)
    text = read_text(encrypted_file_path)
    text = decrypt_text(text, symmetric_key)
    write_text(text, decrypted_file_path)
    print("Текст успешно расшифрован")
    return text, symmetric_key
