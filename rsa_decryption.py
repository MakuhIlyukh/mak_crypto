'''
Скрипт дешифровки по алгоритму RSA
Загружает текст из файла, дешифрует, сохраняет текст в файл.
'''


from mak_crypto.rsa_crypto import (load_private_key,
                                   decrypt_long)


if __name__ == '__main__':
    # Имя файла закрытого ключа
    print(
        'Введите название название файла закрытого ключа'
        '(вместе с суффиксом "_private.pem", если такой имеется): ',
        end=''
    )
    private_key_filename = input()
    print()

    # Пароль для закрытого ключа
    print('Введите пароль для шифрования закрытого ключа. '
          'Если пароль не нужен, оставьте поле ввода пустым. '
          'Используйте только латинские буквы и цифры(ASCII): ',
          end=''
    )
    password_str = input()
    if password_str != '':
        password_b = password_str.encode('utf-8')
    else:
        password_b = None
    print()
    private_key = load_private_key(private_key_filename, password_b)

    # Загрузка зашифрованного текста
    print(
        'Введите название файла, в котором содержится зашифрованный текст: ',
        end=''
    )
    enc_filename = input()
    print()
    with open(enc_filename, 'rb') as f:
        enc_b = f.read()

    # Дешифровка текста и сохранение в файл
    print(
        'Введите название файла, в который '
        'нужно сохранить дешифрованный текст: ',
        end=''
    )
    dec_filename = input()
    print()
    dec_b = decrypt_long(private_key, enc_b)
    with open(dec_filename, 'wb') as f:
        f.write(dec_b)
    
