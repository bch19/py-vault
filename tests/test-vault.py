import pytest
import sys, os
sys.path.append("..")

from pyvault import vault, action

def test_encryption_decryption():
    user_pass = "abcabc"
    plaintext = b"A cryptosystem should be secure even " \
                b"if everything about the system, except " \
                b"the key, is public knowledge." 

    vaultInstance = vault.Vault("CTR", 256)
    ct = vaultInstance.encrypt(plaintext, user_pass)
    pt = vaultInstance.decrypt(ct, user_pass)
    assert(plaintext == pt)

def test_rekey():
    user_pass = "abcabc"
    new_user_pass = "bcbcbc"
    plaintext = b"A cryptosystem should be secure even " \
                b"if everything about the system, except " \
                b"the key, is public knowledge." 

    vaultInstance = vault.Vault("CTR", 256)
    ct = vaultInstance.encrypt(plaintext, user_pass)
    new_ct = vaultInstance.rekey(ct, user_pass, new_user_pass)
    pt = vaultInstance.decrypt(new_ct, new_user_pass)
    assert(plaintext == pt)

def test_encrypt_decrypt_e_key():
    user_pass = "abcabc"
    vaultInstance = vault.Vault("CTR", 256)
    d_key, _ = vaultInstance.get_derived_key(user_pass)
    e_key = os.urandom(32)
    e_key_encrypted = vaultInstance.encrypt_e_key(e_key, d_key)

    e_key1 = vaultInstance.decrypt_e_key(d_key, e_key_encrypted)
    assert(e_key == e_key1)

def test_get_validate_hmac():
    data = b"ABCDEFGHI"
    key = os.urandom(32)
    hmac1 = vault.HMACUtils.get_hmac(key, data)
    result = vault.HMACUtils.validate_hmac(key, data, hmac1)
    assert(result == True)

def test_encrypt_decrypt_AESCTR():
    data = b"ABCDEFGI"
    ct, e_key = vault.AESCTR.encrypt(data)
    pt = vault.AESCTR.decrypt(ct, e_key)
    assert (data == pt)

def test_encrypt_decrypt_AESGCM():
    data = b"ABCDEFGI"
    ct, e_key = vault.AESGCM.encrypt(data)
    pt = vault.AESGCM.decrypt(ct, e_key)
    assert(data == pt)

