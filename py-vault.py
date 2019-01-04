from getpass import getpass
from pyvault import action, message
import os, sys, argparse

PROMPT_MSG = {
    'encrypt': ["New password: ", "Confirm new Password: "],
    'decrypt': ["Password: ", "Confirm Password: "],
    'create': ["New password: ", "Confirm new Password: "],
    'edit': ["Password: ", "Confirm Password: "],
    'view': ["Password: ", "Confirm Password: "],
    'rekey': ["Old Password: ", "New Password: "]
}


def prompt_password(action_type):
    user_pass = getpass(PROMPT_MSG.get(action_type)[0])
    user_pass1 = getpass(PROMPT_MSG.get(action_type)[1])
 
    if action_type != "rekey":
        if user_pass != user_pass1:
            message.print_error("Passwords do not match", 0)
        else:
            return user_pass, user_pass1
    else:
        return user_pass, user_pass1


if __name__ =="__main__":
    parser = argparse.ArgumentParser(
        prog='py-vault',
        description="utility tool to encrypt/decrypt files"
    )
    parser.add_argument('action', 
                        help='action to be performed, options are: '+ 
                            'create, encrypt, decrypt, edit and rekey')
    parser.add_argument('file',
                        help='file to perform action on')
    parser.add_argument('--mode', '-m', 
                        default='CTR',
                        help='encryption mode to be used in create/encrypt, '+
                            'options are CTR/GCM. default CTR')
    parser.add_argument('--key', '-k', default=256, type=int,
                        help='key length to be used in AES, options are 192/256,'+
                            ' default 256')
    args_dict = vars(parser.parse_args())
    action_type = args_dict.get('action')
    file_path = os.path.abspath(args_dict.get('file'))
    mode = args_dict.get('mode')
    k_len = args_dict.get('key')

    user_pass, user_pass1 = prompt_password(action_type)

    if action_type == "encrypt":
        action.encrypt_file(file_path, user_pass, mode, k_len)
    elif action_type == "decrypt":
        action.decrypt_file(file_path, user_pass)
    elif action_type == "create":
        action.create_file(file_path, user_pass, mode, k_len)
    elif action_type == "edit":
        action.edit_file(file_path, user_pass)
    elif action_type == "view":
        action.view_file(file_path, user_pass)
    elif action_type == "rekey":
        action.rekey_file(file_path, user_pass, user_pass1)


    