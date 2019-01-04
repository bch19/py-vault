import os

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
    default_hash = 'SHA256'
    support_modes = ['CTR', 'GCM']
    support_k_lens = [192, 256]
    default_msg = b"hmac password hash"

    def __init__(self, mode: str, k_len: int):
        self.mode = mode
        self.k_len = k_len

    def encrypt(self, plaintext, user_pass):
        d_key, salt = self.get_derived_key(user_pass)
        
        encrypt_mode = ENCRYPTION_MODE.get(self.mode)
        ct, e_key = encrypt_mode.encrypt(plaintext)

        e_key_encrypted = self.encrypt_e_key(e_key, d_key)        
        ct = ct + e_key_encrypted + salt
        return ct

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
        pt = encrypt_mode.decrypt(ciphertext, e_key)

        return pt

    def rekey(self, ciphertext, old_user_pass, new_user_pass):
        salt = ciphertext[-SALT_SIZE:]
        e_key_info = ciphertext[-(HMAC_SIZE+IV_SIZE+HMAC_SIZE+SALT_SIZE):-SALT_SIZE]
        ciphertext = ciphertext[:-(HMAC_SIZE+IV_SIZE+HMAC_SIZE+SALT_SIZE)]

        old_d_key, _ = self.get_derived_key(old_user_pass, salt)
        e_key = self.decrypt_e_key(old_d_key, e_key_info)
        new_d_key, new_salt = self.get_derived_key(new_user_pass)
        new_e_key_info = self.encrypt_e_key(e_key, new_d_key)  

        ct = ciphertext + new_e_key_info + new_salt
        return ct

    @classmethod
    def get_derived_key(cls, user_pass: str, salt=None):
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

    @classmethod
    def encrypt_e_key(cls, e_key, d_key):
        e_key_encrypted, _ = AESCTR.encrypt(e_key, d_key)
        return e_key_encrypted

    @classmethod
    def decrypt_e_key(cls, d_key, e_key_info):
        e_key = AESCTR.decrypt(e_key_info, d_key)
        return e_key

    @classmethod
    def get_hmac(cls, key, data):
        h = hmac.HMAC(key, hashes.SHA256(), backend=BACKEND)
        h.update(data)
        return h.finalize()

    @classmethod
    def validate_hmac(cls, key, data, hmac_check):
        h = Vault.get_hmac(key, data)
        if h != hmac_check:
            return False
        else:
            return True


# Base class for all encryption mode: 'CTR', 'GCM', 'CBC'...
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
        ct_hmac = Vault.get_hmac(e_key, ct)
        ct = ct + iv + ct_hmac
        return (ct, e_key)

    @staticmethod
    def decrypt(ciphertext, e_key):
        ct_hmac = ciphertext[-HMAC_SIZE:]
        iv = ciphertext[-(IV_SIZE+HMAC_SIZE):-HMAC_SIZE]
        ciphertext = ciphertext[:-(IV_SIZE+HMAC_SIZE)]

        validate = Vault.validate_hmac(e_key, ciphertext, ct_hmac)

        if validate:
            decryptor = Cipher(
                algorithms.AES(e_key), 
                modes.CTR(iv), 
                backend=BACKEND
            ).decryptor()
            pt = decryptor.update(ciphertext) + decryptor.finalize()
            return pt
        else:
            raise Exception("HMAC of CT Not validated")


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
        ct_hmac = Vault.get_hmac(e_key, ct)
        ct = ct + iv + encryptor.tag + ct_hmac
        return (ct, e_key)

    @staticmethod
    def decrypt(ciphertext, e_key):
        ct_hmac = ciphertext[-HMAC_SIZE:]
        tag = ciphertext[-(TAG_SIZE+HMAC_SIZE):-HMAC_SIZE]
        iv = ciphertext[-(IV_SIZE+TAG_SIZE+HMAC_SIZE):-(TAG_SIZE+HMAC_SIZE)]
        ciphertext = ciphertext[:-(IV_SIZE+TAG_SIZE+HMAC_SIZE)]

        validate = Vault.validate_hmac(e_key, ciphertext, ct_hmac)
        
        if validate:
            decryptor = Cipher(
                algorithms.AES(e_key),
                modes.GCM(iv, tag),
                backend=BACKEND
            ).decryptor()
            pt = decryptor.update(ciphertext) + decryptor.finalize()
            return pt
        else:
            raise Exception("HMAC of CT Not validated")

ENCRYPTION_MODE = {
    'CTR' : AESCTR,
    'GCM' : AESGCM
}
