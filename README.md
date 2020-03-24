# stedap
Simple Text Encryption Decryption Application for PGP

This application lets you encrypt and decrypt text easily using Pretty Good Privacy.

It is written in Python using the gnupg library

The GPG home is stored in a newly created directory in /tmp/tmp(randomly generated digits). The GPG home is deleted when the application is closed.

There is a Linux executable in the dist/ directory.

Improvements that will be made over time:
  - Add the option to sign / verify signature
  - Add the option to encrypt / decrypt files

To start : 
```
cd path/to/directory
python main.py
```
