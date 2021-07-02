'''
Создает закрытый и открытые ключи для алгоритма RSA.
Сохраняет их в файлы
'''


from mak_crypto.rsa_crypto import (create_private_key,
                                   save_private_key,
                                   save_public_key,
                                   VALID_KEY_SIZES)


if __name__ == '__main__':
    # длина закрытого и открытого ключа
    n_bits = int(input('Введите длину закрытого ключа: '))
    print()
    if n_bits not in VALID_KEY_SIZES:
        raise ValueError(
            'Недопустимый размер ключа. '
            f'Допустимы следующие: {VALID_KEY_SIZES}'
        )

    # название файла закрытого ключа
    print(
        'Введите префикс для названия файла, в который '
        'будет сохранен закрытый ключ: ',
        end=''
    )
    private_key_prefix = input()
    print(f'Закрытый ключ будет сохранен в {private_key_prefix}_private.pem')
    print()

    # название файла для открытого ключа
    print(
        'Введите префикс для названия файла, в который '
        'будет сохранен открытый ключ: ',
        end=''
    )
    public_key_prefix = input()
    print(f'Открытый ключ будет сохранен в {public_key_prefix}_public.pem')
    print()

    # Пароль для закрытого ключа
    print('Введите пароль для шифрования закрытого ключа. '
          'Если пароль не нужен, оставьте поле ввода пустым. '
          'Используйте только латинские буквы и цифры(ASCII): ',
          end=''
    )
    password_str = input()
    print()
    if password_str != '':
        password_b = password_str.encode('utf-8')
    else:
        password_b = None
    
    # Создание ключей и сохранение их 
    private_key = create_private_key(n_bits=n_bits)
    public_key = private_key.public_key()
    save_private_key(private_key_prefix + '_private', private_key, password_b)
    save_public_key(public_key_prefix + '_public', public_key)
