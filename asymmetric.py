def encrypt_symmetric_key(symmetric_key: bytes, public_key: RSAPublicKey) -> bytes:
    """
    Шифрование ключа с помощью RSA-OAEP
    
    Args:
        symmetric_key (bytes): Симметричный ключ для шифрования
        public_key (RSAPublicKey): Открытый ключ RSA для шифрования
    
    Returns:
        bytes: Зашифрованный симметричный ключ
    
    Raises:
        Exception: Ошибка при шифровании
    """
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_symmetric_key(encrypted_key: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Дешифровка ключа с помощью RSA-OAEP
    
    Args:
        encrypted_key (bytes): Зашифрованный симметричный ключ
        private_key (RSAPrivateKey): Закрытый ключ RSA для дешифрования
    
    Returns:
        bytes: Расшифрованный симметричный ключ
    
    Raises:
        Exception: Ошибка при дешифровании
    """
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def get_asymmetric_key() -> tuple:
    """
    Генерация ключей для асимметричного алгоритма
    
    Returns:
        tuple: Кортеж (private_key, public_key) - закрытый и открытый ключи RSA
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    return private_key, public_key
