from logic import enc_logic, dec_logic, gen_logic
from load_and_save import json_parser
import argparse


def parser() -> argparse.Namespace:
    """
    Создает и настраивает парсер аргументов командной строки.
    
    Определяет три взаимно исключающих режима работы программы:
    - генерация ключей с указанием длины
    - шифрование файла
    - дешифрование файла
    
    Также принимает необязательные аргументы для указания путей
    к входному и выходному файлам.
    
    Returns:
        argparse.Namespace: Объект с распарсенными аргументами командной строки,
                           содержащий:
                           - generation: длина ключа (если выбран режим генерации)
                           - encryption: флаг режима шифрования
                           - decryption: флаг режима дешифрования
                           - input: путь к входному файлу
                           - output: путь к выходному файлу
    
    Raises:
        SystemExit: Если не указан ни один из обязательных режимов работы.
    """
    parser = argparse.ArgumentParser(
        description='Программа для шифрования и дешифрования файлов с использованием '
                   'симметричного (3DES) и асимметричного (RSA) шифрования.'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', type=int, 
                      help='Запускает режим генерации ключей. Укажите длину ключа: 64, 128 или 192 бит')
    group.add_argument('-enc', '--encryption', action='store_true', 
                      help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', 
                      help='Запускает режим дешифрования')
    parser.add_argument('input', nargs='?', 
                       help='Путь к исходному файлу (для шифрования/дешифрования)')
    parser.add_argument('output', nargs='?', 
                       help='Путь к файлу результата (для шифрования/дешифрования)')
    args = parser.parse_args()
    return args
    

def main() -> None:
    """
    Главная функция программы.
    
    Парсит аргументы командной строки, загружает настройки из файла
    и запускает соответствующий режим работы:
    - генерация ключей (с проверкой допустимой длины)
    - шифрование файла
    - дешифрование файла
    
    Если пути к файлам не указаны в командной строке, используются
    значения из файла настроек settings.json.
    
    Raises:
        SystemExit: Если указана недопустимая длина ключа при генерации.
    """
    action = parser()
    settings = json_parser()
    
    if settings is None:
        print("Ошибка: не удалось загрузить настройки из settings.json")
        return
    
    input_path = action.input
    output_path = action.output
    
    if action.encryption:
        # Режим шифрования
        if input_path is None:
            input_path = settings["initial_file_path"]
        if output_path is None:
            output_path = settings["encrypted_file_path"]
        enc_logic(settings, input_path, output_path)
        
    elif action.decryption:
        # Режим дешифрования
        if input_path is None:
            input_path = settings["encrypted_file_path"]
        if output_path is None:
            output_path = settings["decrypted_file_path"]
        dec_logic(settings, input_path, output_path)
        
    elif action.generation is not None:
        # Режим генерации ключей
        if action.generation in [64, 128, 192]:
            gen_logic(settings, action.generation)
        else:
            print("Некорректная длина ключа. Допустимые значения: 64, 128, 192")


if __name__ == "__main__":
    main()
