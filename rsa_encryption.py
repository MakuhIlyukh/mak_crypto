'''
Скрипт шифрования по алгоритму RSA
Загружает текст из файла, шифрует, сохраняет текст в файл.
'''


from mak_crypto.rsa_crypto import (load_public_key,
                                   encrypt_long)


if __name__ == '__main__':
    # Загрузка открытого ключа
    print(
        'Введите название название файла открытого ключа'
        '(вместе с суффиксом "_public.pem", если такой имеется): ',
        end=''
    )
    public_key_filename = input()
    print()
    public_key = load_public_key(public_key_filename)

    # Загрузка шифруемого текста
    print(
        'Введите название файла, в котором содержится текст, '
        'который нужно зашифровать: ',
        end=''
    )
    original_text_filename = input()
    print()
    with open(original_text_filename, 'rb') as f:
        msg_b = f.read()

    # Шифрование текста и сохранение в файл
    print(
        'Введите название файла, в который '
        'нужно сохранить зашифрованный текст: ',
        end=''
    )
    enc_filename = input()
    print()
    enc_b = encrypt_long(public_key, msg_b)
    with open(enc_filename, 'wb') as f:
        f.write(enc_b)
