# Why you may need it

Sometimes you want to store your password into your shell scripts
but it's not very safe to keep raw passwords in it

This module can help you to solve this problem by keeping your passwords encrypted.

The idea is you have your ssh key which protected with master password
and there is an ssh-agent which contains your ssh key, so you can use it as
encryption key, until you have your key in ssh-agent you can decrypt your passwords
in your shell scripts, while if ssh key is in not in your ssh-agent you(or somebody else) can't
use it to encrype/decrypt passwords or other sensitive data, here how you can use it:
We add your ssh key into ssh-agent:

    /usr/bin/ssh-add -t 1d -k ~/.ssh/id_rsa

We enter master password and now we have ssh key in our ssh-agent,
Now we can use it to encrypt passwords or other sensitive data:

    ssh-crypt -e -s 'testpassword'

we get string which contains your encrypted password, copy it, we can use it further,
lets write shell script:

    !/bin/bash

    PASS='{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'

    mysql -h localhost -u testuser -p$(ssh-crypt -d -s $PASS)

so now you don't have raw password in you shell script, while this encrypted password
can be decrypted only when you ssh key been added in your ssh-agent before


Also you can use it just to encrypt/decrypt files like:

    ssh-crypt -e -i /tmp/rawfile -o /tmp/encrypted_file
    ssh-crypt -d -i /tmp/encrypted_file -o /tmp/rawfile


# How it works

When you encrypt your password it generates random bytes, which signed by you ssh key
from your ssh-agent, then it creates sha3_256 from this signature and uses it as a key
to encrypt your data with AES and creating base85 of it if binary mode is not enabled

![How encryption works](/data/encryption.png)

When you decrypt your password it takes random bytes until ":" sign, signs it with your ssh key,
creates sha3_256 from it and uses it as a AES key to decrypt the rest of data

![How decryption works](/data/decryption.png)

# How to install it

    pip install ssh-crypt


# Options

-h, --help

Prints brief usage information.

-e, --encrypt

Encrypt incomming data

Examples:

    ssh-crypt -e -s 'testpassword'
    echo 'testpassword' | ssh-crypt -e


-d, --decrypt

Decrypt incomming data, if not set encrypt mode will be enabled

Examples:

    ssh-crypt -d -s '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'
    echo '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5' | ssh-crypt -e


-i, --input

Input file, if not set STDIN will be used

Examples:

    ssh-crypt -e -i /tmp/testfile
    ssh-crypt -d -i /tmp/testfile
    ssh-crypt -e -b -i /tmp/testfile


-o, --output

Output file, if not set STDOUT will be used

Examples:

    ssh-crypt -e -s 'testpassword' -o /tmp/testfile
    echo 'testpassword' | ssh-crypt -e -o /tmp/testfile


-s, --string

Use passed string as an input data

Examples:

    ssh-crypt -e -s 'testpassword'
    ssh-crypt -d -s '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'


-b, --binary

Encrypt or decrypt binary data

Examples:

    ssh-crypt -e -s 'testpassword' -b -o /tmp/testfile
    ssh-crypt -e -i /tmp/testfile -b


# Bugs

See github issues: https://github.com/Sets88/ssh-crypt/issues
