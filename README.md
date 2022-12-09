# Why you may need it

Sometimes you want to keep your password inside your shell scripts
but it's not very safe to have raw passwords in it

This module can help you to solve this problem by keeping your passwords encrypted.

The idea is you have your ssh key which protected with master password(or a special device containing a key)
and there is an ssh-agent which can keep your ssh key(or use you key device), so you can use you key as an
encryption key, until you have your key in ssh-agent you can decrypt your passwords
inside your shell scripts, but after your ssh key been removed from your ssh-agent you(or somebody else) can't
use it to encrypt/decrypt passwords or other sensitive data, here how you can use it:
You add your ssh key into ssh-agent:

    /usr/bin/ssh-add -t 1d -k ~/.ssh/id_rsa

You enter master password and now you have ssh key in your ssh-agent,
Now you can use it to encrypt passwords or other sensitive data:

    ssh-crypt -e -s 'testpassword'

You get string which contains your encrypted password, copy it, you can use it further,
lets write a shell script:

    !/bin/bash

    PASS='{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'

    mysql -h localhost -u testuser -p$(ssh-crypt -d -s $PASS)

now you don't have raw password inside your shell script anymore, while this encrypted password
can be decrypted only if your ssh key still in your ssh-agent


Also you can use it just to encrypt/decrypt files like here:

    ssh-crypt -e -i /tmp/rawfile -o /tmp/encrypted_file
    ssh-crypt -d -i /tmp/encrypted_file -o /tmp/rawfile


# How it works

When you encrypt your password it generates random bytes, which signed by you ssh key
from your ssh-agent, then it creates sha3_256 from this signature and uses it as a key
to encrypt your data with AES and creating base85 of it if binary mode is not enabled

![How encryption works](/data/encryption.png)

When you decrypt your password it takes nonce bytes from the string you pass, signs it with your ssh key,
creates sha3_256 from it and uses it as a AES key to decrypt the rest of data

![How decryption works](/data/decryption.png)


# How to install it

    pip install ssh-crypt

# How to use it in python scripts

```python
from ssh_crypt import E

super_secret_password = str(E('{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'))
```

# Using yubiko keys to keep your ssh key

## Install yubico-piv-tool

Download it from https://developers.yubico.com/yubico-piv-tool/Releases/ or from (brew, apt, yum, or pacman)

## SSH Key

Generate new key

    ssh-keygen -b 2048 -t rsa -m PEM

or alter current key to PEM format

    ssh-keygen -p -m PEM

unfortunately 4096 and longer RSA keys are not supported by PIV specification

## Import key to yubikey

Slot 9a only can be used to store rsa key

    yubico-piv-tool --touch-policy=cached -s 9a -a import-key --pin-policy=once -i id_rsa

## Add card to ssh-agent

Remove old card if exists (as if it was previously added next command will not work even if "ssh-add -D" executed)

    ssh-add -e /usr/local/lib/libykcs11.dylib

Add new card

    ssh-add -s /usr/local/lib/libykcs11.dylib

Enter Yubikey PIN when it's asked for passphrase for PKCS#11
All set up now but you have to confirm decryption by touching yubico button
if it't not convinient for you to touch button all the time you can disable this behaviour by removeing
"--touch-policy=cached" param during key import


# Use it with apps which demands config files which have to contain some token or password

Just create a shell script with which you can access your application here is an example:

```bash
#! /bin/bash

TOKEN='{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'

CONFIG="apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: ***somesertdata**
    server: https://kuber-api-host:6443
  name: app
contexts:
- context:
    cluster: app
    namespace: some-namespace
    user: max
  name: app
current-context: app
kind: Config
preferences: {}
users:
- name: max
  user:
    token:
     $(ssh-crypt -d -s $TOKEN)
"

kubectl --kubeconfig <(echo "$CONFIG") $*
```

# Using SSH-Agent Forwarding

There is an option to use scripts with encrypted passwords in it on remote hosts, by connecting to it via ssh like this

    ssh -A user@somehost

"-A" parameter enables SSH-Agent forwarding.
**Beware!** never use this technique if you don't fully trust remote host
as someone who has enough permissions on that host may use your ssh agent for bad purpose 


# Options

-h, --help

Prints brief usage information.

-e, --encrypt

Encrypt incomming data

Examples:

    ssh-crypt -e -s 'testpassword'
    echo 'testpassword' | ssh-crypt -e


-d, --decrypt

Decrypt incomming data, encrypt mode will be enabled if not set

Examples:

    ssh-crypt -d -s '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'
    echo '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5' | ssh-crypt -e


-i, --input

Input file, STDIN will be used if not set

Examples:

    ssh-crypt -e -i /tmp/testfile
    ssh-crypt -d -i /tmp/testfile
    ssh-crypt -e -b -i /tmp/testfile


-o, --output

Output file, STDOUT will be used if not set

Examples:

    ssh-crypt -e -s 'testpassword' -o /tmp/testfile
    echo 'testpassword' | ssh-crypt -e -o /tmp/testfile


-s, --string

Use passed string as an input data

Examples:

    ssh-crypt -e -s 'testpassword'
    ssh-crypt -d -s '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'


-b, --binary

Not use base85(used to make encrypted data look more like text file, to allow to copy it inside shell scripts) for payload

Examples:

    ssh-crypt -e -s 'testpassword' -b -o /tmp/testfile
    ssh-crypt -e -i /tmp/testfile -b


-k, --key

Pick key from ssh-agent keys list by its comment

Examples:

    ssh-crypt -e -s 'testpassword' -k testkey
    ssh-crypt -d -s '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5' -k testkey


# Bugs

See github issues: https://github.com/Sets88/ssh-crypt/issues
