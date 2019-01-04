py-vault
========

Python utility tool to encrypt/decrypt your common files using AES.
* Supports common modes of operation (CTR, GCM)
* Supports 192 and 256 key length currently.
* Implements Encrypt-then-HMAC to provide confidentiality and integrity of data
* Uses PBKDF2 on user passphrase to provide two levels of encryption


Usage
--------
To create a file and encrypt it:
```
python py-vault.py create {file_path}
```
To view a encrypted file without decrypting it:
```
python py-vault.py view {file_path}
```
To encrypt a generic file:
```
python py-vault.py encrypt {file_path}
```
To decrypt a generic file:
```
python py-vault.py decrypt {file_path}
```
To edit a file without decrypting it: 
```
python py-vault.py edit {file_path}
```
To rekey a file with a new password:
```
python py-vault.py rekey {file_path}
```
Future plan:
* Introduce dynamic variable creation/update/deletion in JSON/YAML files


