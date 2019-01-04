import os, sys

from pyvault import message

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


SALT_SIZE = 16
KDF_KEY_SIZE = 32
HMAC_SIZE = 32
IV_SIZE = 16
TAG_SIZE = 16
BACKEND = default_backend()


class VaultMetadata:
    def __init__(self, mode: str, k_len: int):
        self.mode = mode
        self.k_len = k_len


class Vault:
    support_modes = ['CTR', 'GCM']
    support_k_lens = [192, 256]

    def __init__(self, mode: str, k_len: int):
        self.mode = mode
        self.k_len = k_len

    def encrypt(self, plaintext, user_pass):
        d_key, salt = self.get_derived_key(user_pass)
        
        encrypt_mode = ENCRYPTION_MODE.get(self.mode)
        ct, e_key = encrypt_mode.encrypt(plaintext)

        e_key_encrypted = self.encrypt_e_key(e_key, d_key)        
        return ct + e_key_encrypted + salt

    def decrypt(self, ciphertext, user_pass):        
        # extract encryption info from file
        salt = ciphertext[-SALT_SIZE:]
        e_key_info = ciphertext[-(HMAC_SIZE+IV_SIZE+HMAC_SIZE+SALT_SIZE):-SALT_SIZE]
        ciphertext = ciphertext[:-(HMAC_SIZE+IV_SIZE+HMAC_SIZE+SALT_SIZE)]

        #calculate derived key from user_pass
        d_key, _ = self.get_derived_key(user_pass, salt)   
        e_key = self.decrypt_e_key(d_key, e_key_info)

        # key is authenticated, proceed decryption
        encrypt_mode = ENCRYPTION_MODE.get(self.mode)
        return encrypt_mode.decrypt(ciphertext, e_key)


    def rekey(self, ciphertext, old_user_pass, new_user_pass):
        salt = ciphertext[-SALT_SIZE:]
        e_key_info = ciphertext[-(HMAC_SIZE+IV_SIZE+HMAC_SIZE+SALT_SIZE):-SALT_SIZE]
        ciphertext = ciphertext[:-(HMAC_SIZE+IV_SIZE+HMAC_SIZE+SALT_SIZE)]

        old_d_key, _ = self.get_derived_key(old_user_pass, salt)
        e_key = self.decrypt_e_key(old_d_key, e_key_info)
        new_d_key, new_salt = self.get_derived_key(new_user_pass)
        new_e_key_info = self.encrypt_e_key(e_key, new_d_key)  

        return ciphertext + new_e_key_info + new_salt


    @staticmethod
    def get_derived_key(user_pass: str, salt=None):
        if salt is None:
            salt = os.urandom(SALT_SIZE)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KDF_KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=BACKEND
        )
        e_key = kdf.derive(user_pass.encode('utf-8'))
        return (e_key, salt)

    @staticmethod
    def encrypt_e_key(e_key, d_key):
        e_key_encrypted, _ = AESCTR.encrypt(e_key, d_key)
        return e_key_encrypted

    @staticmethod
    def decrypt_e_key(d_key, e_key_info):
        return AESCTR.decrypt(e_key_info, d_key)


class HMACUtils:
    @staticmethod
    def get_hmac(key, data):
        h = hmac.HMAC(key, hashes.SHA256(), backend=BACKEND)
        h.update(data)
        return h.finalize()

    @staticmethod
    def validate_hmac(key, data, hmac_check):
        h = HMACUtils.get_hmac(key, data)
        if h != hmac_check:
            return False
        else:
            return True


# Base class for all encryption mode: 'CTR', 'GCM'...
class AES:
    @staticmethod
    def encrypt():
        pass

    @staticmethod
    def decrypt():
        pass

# Class for AES CTR
class AESCTR(AES):
    @staticmethod
    def encrypt(plaintext, e_key=None):
        if not e_key:
            e_key = os.urandom(32)
        iv = os.urandom(IV_SIZE)

        encryptor = Cipher(
            algorithms.AES(e_key),
            modes.CTR(iv),
            backend=BACKEND
        ).encryptor()

        ct = encryptor.update(plaintext) + encryptor.finalize()
        ct_hmac = HMACUtils.get_hmac(e_key, ct)
        ct = ct + iv + ct_hmac
        return (ct, e_key)

    @staticmethod
    def decrypt(ciphertext, e_key):
        ct_hmac = ciphertext[-HMAC_SIZE:]
        iv = ciphertext[-(IV_SIZE+HMAC_SIZE):-HMAC_SIZE]
        ciphertext = ciphertext[:-(IV_SIZE+HMAC_SIZE)]

        validate = HMACUtils.validate_hmac(e_key, ciphertext, ct_hmac)

        if validate:
            decryptor = Cipher(
                algorithms.AES(e_key), 
                modes.CTR(iv), 
                backend=BACKEND
            ).decryptor()
            pt = decryptor.update(ciphertext) + decryptor.finalize()
            return pt
        else:
            message.print_error("File decryption failed", 1)


# Class for AES GCM
class AESGCM(AES):
    @staticmethod
    def encrypt(plaintext, e_key=None):
        if not e_key:
            e_key = os.urandom(32)
        iv = os.urandom(IV_SIZE)
        encryptor = Cipher(
            algorithms.AES(e_key), 
            modes.GCM(iv), 
            backend=BACKEND
        ).encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()
        ct_hmac = HMACUtils.get_hmac(e_key, ct)

        return (ct+iv+encryptor.tag+ct_hmac, e_key)

    @staticmethod
    def decrypt(ciphertext, e_key):
        ct_hmac = ciphertext[-HMAC_SIZE:]
        tag = ciphertext[-(TAG_SIZE+HMAC_SIZE):-HMAC_SIZE]
        iv = ciphertext[-(IV_SIZE+TAG_SIZE+HMAC_SIZE):-(TAG_SIZE+HMAC_SIZE)]
        ciphertext = ciphertext[:-(IV_SIZE+TAG_SIZE+HMAC_SIZE)]

        validate = HMACUtils.validate_hmac(e_key, ciphertext, ct_hmac)
        
        if validate:
            decryptor = Cipher(
                algorithms.AES(e_key),
                modes.GCM(iv, tag),
                backend=BACKEND
            ).decryptor()
            pt = decryptor.update(ciphertext) + decryptor.finalize()
            return pt
        else:
            message.print_error("File decryption failed.", 1)

ENCRYPTION_MODE = {
    'CTR' : AESCTR,
    'GCM' : AESGCM
}
