import os, sys, re, tempfile
from subprocess import call
from getpass import getpass

from pyvault import vault, message

LEN_PREFIX = 20
EDITOR = os.environ.get('EDITOR', 'vim')


def read_file_as_bytes(file_path):
    with open(file_path, "rb") as src_file:
        src_content = src_file.read()
    return src_content

def write_file_as_bytes(file_path, content, metadata=None):
    if metadata is not None:
        content = b"$PYVAULT;AES" + metadata.mode.encode('utf-8') \
                + str(metadata.k_len).encode('utf-8') + ';\n'.encode('utf-8')\
                + content
    with open(file_path, "wb") as dst_file:
        dst_file.write(content)

def parse_metadata(data): 
    meta = data[0:LEN_PREFIX].decode('utf-8')
    meta_pattern = re.compile(r"\$PYVAULT\;AES([A-Z]+)(\d+)\;")
    meta_match = meta_pattern.match(str(meta))
    mode = meta_match.group(1)
    if mode not in vault.Vault.support_modes:
        message.print_error("Encryption Mode not supported", 0)

    k_len = meta_match.group(2)
    if int(k_len) not in vault.Vault.support_k_lens:
        message.print_error("Key length not supported", 0)

    return vault.VaultMetadata(mode, k_len), data[LEN_PREFIX:]


def create_file(file_path, user_pass, mode="CTR", k_len=256):
    if os.path.isfile(file_path):
        message.print_error("Destination file already exists", 0)

    vaultInstance = vault.Vault(mode, k_len)
    call([EDITOR, file_path])
    pt = read_file_as_bytes(file_path)
    ct = vaultInstance.encrypt(pt, user_pass)
    write_file_as_bytes(file_path, ct, vault.VaultMetadata(mode, k_len))
    message.print_success("File created and encryption successful")

def edit_file(file_path, user_pass):
    # get encrypted file content then decrypt
    content = read_file_as_bytes(file_path)
    metadata, content = parse_metadata(content)
    vaultInstance = vault.Vault(metadata.mode, metadata.k_len)

    pt = vaultInstance.decrypt(content, user_pass)

    with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
        # write decrypted content in temp file
        tf.write(pt)  
        tf.flush()  
        call([EDITOR, '+set backupcopy=yes', tf.name])
        # read new decrypted content edited by user
        tf.seek(0)
        pt = tf.read()
    
    #encrypt new edited content then write to file
    new_ct = vaultInstance.encrypt(pt, user_pass)
    write_file_as_bytes(file_path, new_ct, metadata)
    message.print_success("File edited and encryption successful")


def view_file(file_path, user_pass):
    content = read_file_as_bytes(file_path)
    metadata, content = parse_metadata(content)
    vaultInstance = vault.Vault(metadata.mode, metadata.k_len)

    pt = vaultInstance.decrypt(content, user_pass)

    with tempfile.NamedTemporaryFile(suffix=".tmp", mode="r+b") as tf:
        # write decrypted content in temp file
        tf.write(pt)  
        tf.flush()  
        call([EDITOR, tf.name])


def encrypt_file(file_path, user_pass, mode="CTR", k_len=256):
    vaultInstance = vault.Vault(mode, k_len)
    ct = vaultInstance.encrypt(read_file_as_bytes(file_path), user_pass)
    write_file_as_bytes(file_path, ct, vault.VaultMetadata(mode, k_len))
    message.print_success("File encryption successful")

def decrypt_file(file_path, user_pass):
    ct = read_file_as_bytes(file_path)
    metadata, ct = parse_metadata(ct)
    vaultInstance = vault.Vault(metadata.mode, metadata.k_len)
    pt = vaultInstance.decrypt(ct, user_pass)
    write_file_as_bytes(file_path, pt)
    message.print_success("File decryption successful")

def rekey_file(file_path, user_pass, new_user_pass):
    ct = read_file_as_bytes(file_path)
    metadata, ct = parse_metadata(ct)
    vaultInstance = vault.Vault(metadata.mode, metadata.k_len)
    new_ct = vaultInstance.rekey(ct, user_pass, new_user_pass)
    write_file_as_bytes(file_path, new_ct, metadata)
    message.print_success("File rekey successful")
