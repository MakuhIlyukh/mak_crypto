import unittest
from mak_crypto import rsa_crypto

class RsaMethodsTestCase(unittest.TestCase):
    def test_create_private_key(self):
        with self.subTest():
            with self.assertRaises(ValueError):
                rsa_crypto.create_private_key(276)
        for n_bits in rsa_crypto.VALID_KEY_SIZES:
            with self.subTest(n_bits=n_bits):
                rsa_crypto.create_private_key(n_bits=n_bits)
    
    def test_on_hamlet(self):
        '''Загружает ключ, шифрует, дешифрует,
         проверяет эквивалентность.'''
        public_key = rsa_crypto.load_public_key('test/data/public.pem')
        private_key = rsa_crypto.load_private_key('test/data/private.pem')
        with open('test/data/hamlet.txt', 'rb') as f:
            msg_b = f.read()
        with open('test/data/hamlet_dec.txt', 'rb') as f:
            dec_b = f.read()
        enc_b2 = rsa_crypto.encrypt_long(public_key, msg_b)
        dec_b2 = rsa_crypto.decrypt_long(private_key, enc_b2)
        self.assertEqual(dec_b, msg_b)
        self.assertEqual(dec_b, dec_b2)

    def test_on_hamlet2(self):
        '''Создает ключи разных размеров, шифрует, дешифрует
         проверяет эквивалентность'''
        with open('test/data/hamlet.txt', 'rb') as f:
            msg_b = f.read()
        for n_bits in rsa_crypto.VALID_KEY_SIZES:
            with self.subTest(n_bits=n_bits):
                private_key = rsa_crypto.create_private_key(n_bits)
                public_key = private_key.public_key()
                enc_b = rsa_crypto.encrypt_long(public_key, msg_b)
                dec_b = rsa_crypto.decrypt_long(private_key, enc_b)
                self.assertEqual(msg_b, dec_b)

if __name__ == '__main__':
    unittest.main()