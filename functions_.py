import os
import gnupg
import tempfile
import re
from pprint import pprint

gnupg_path = tempfile.mkdtemp()

gpg = gnupg.GPG(gnupghome=gnupg_path)

def import_from_file_name(path):
    if isinstance(path, str):
        with open(path, "r") as f:
            kkey_ = f.read()
            imported_key = gpg.import_keys(kkey_)


def burn_gnugp():
    os.system("rm -r " + gnupg_path)

def generate_new_keys(name, email, comment, length, expiry_d, passph):
    input_data = gpg.gen_key_input(key_type="RSA",
                                   name_real=name,
                                   name_email=email,
                                   name_comment=comment,
                                   key_length=length,
                                   expire_date=expiry_d,
                                   passphrase=passph)
    key = gpg.gen_key(input_data)

def is_email(email):  
    regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    # pass the regualar expression 
    # and the string in search() method 
    return (re.search(regex,email))
    
def key_present():
    if len(gpg.list_keys()) == 1 and len(gpg.list_keys(True)) == 1:
        return [True,True]
    if len(gpg.list_keys()) == 1 and len(gpg.list_keys(True)) == 0:
        return [True, False]
    if len(gpg.list_keys()) == 0 and len(gpg.list_keys(True)) ==0:
        return [False, False]

def burn_keys():
    fp = gpg.list_keys()[0]['fingerprint']
    if fp == []:
        fp = gpg.list_keys(True)[0]['fingerprint']
    conf_priv = str(gpg.delete_keys(fp, True, passphrase="")) #Works whitout passphrase
    conf_pub = str(gpg.delete_keys(fp))
    
    if gpg.list_keys(True) == [] and gpg.list_keys(True) == []:
        return True
    else:
        return False

def get_key_text(pubosec, *passphee):
    if pubosec:
        return gpg.export_keys(gpg.list_keys(True)[0]["keyid"], True, passphrase=passphee)
    else:
        return gpg.export_keys(gpg.list_keys()[0]["keyid"])

def get_key_file_name():
    return "0x"+gpg.list_keys()[0]["keyid"][8:16]

def extract_email_from_str(string_):
    match = re.search(r'[\w\.-]+@[\w\.-]+', string_)
    return match.group(0)

def pgp_encrypt(text):
    email_ = extract_email_from_str(gpg.list_keys()[0]['uids'][0])
    status = gpg.encrypt(
            text,
            recipients=email_,
            always_trust=True)
    print('ok: ', status.ok)
    print('status: ', status.status)
    print('stderr: ', status.stderr)
    return status

def pgp_decrypt(text, passph):
    status = gpg.decrypt(text, always_trust=True, passphrase=passph)
    print('ok: ', status.ok)
    print('status: ', status.status)
    print('stderr: ', status.stderr)
    return status




#dirpath = tempfile.mkdtemp()