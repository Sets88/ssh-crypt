# Why you may need it

[![PyPI version](https://img.shields.io/pypi/v/ssh-crypt.svg?color=blue)](https://pypi.org/project/ssh-crypt)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/license/bsd-3-clause/)

[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](Black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Sometimes, you may need to store passwords within your shell scripts, but doing so in plain text is a major security risk.

Fortunately, this module can help you keep your passwords encrypted and secure.

Here's how it works: you protect your ssh key with a master password or a special device, and then use the ssh-agent
to keep your ssh key (or use your key device). This allows you to use your key as an encryption key, and decrypt your
passwords within your shell scripts while your key is in the ssh-agent. However, once your ssh key is removed
from the ssh-agent, neither you nor anyone else can use it to encrypt or decrypt sensitive data.
To use this module, simply add your ssh key to the ssh-agent:

    /usr/bin/ssh-add -t 1d -k ~/.ssh/id_rsa

After entering your master password, your ssh key is now stored in the ssh-agent. You can use it
to encrypt passwords or other sensitive data securely:

    ssh-crypt -e -s 'testpassword'

Once you have encrypted your password, you will receive a string containing the encrypted data.
You can copy this string and use it as needed. To automate this process, you can write a shell script:

    !/bin/bash

    PASS='{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'

    mysql -h localhost -u testuser -p$(ssh-crypt -d -s $PASS)

By using this module, you no longer need to store raw passwords within your shell scripts.
Instead, you can use encrypted passwords that can only be decrypted if your ssh key is still stored in
the ssh-agent. This ensures that your sensitive data remains secure and protected from unauthorized access.

In addition to encrypting and decrypting passwords, this module can also be used to encrypt and
decrypt files. This provides an extra layer of security for your sensitive data, ensuring
that it remains protected from prying eyes.

    ssh-crypt -e -i /tmp/rawfile -o /tmp/encrypted_file
    ssh-crypt -d -i /tmp/encrypted_file -o /tmp/rawfile


# How it works

When you encrypt your password using this module, it generates random bytes that are signed by
your ssh key from your ssh-agent. It then creates a sha3_256 hash from this signature and uses
it as a key to encrypt your data with AES. If binary mode is not enabled, it also creates
a base85 representation of the encrypted data. This process ensures that your sensitive data
is encrypted using a strong key and is protected from unauthorized access.

![How encryption works](/data/encryption.png)

When you decrypt your password using this module, it takes the nonce bytes from the string
you pass and signs it with your ssh key. It then creates a sha3_256 hash from this signature
and uses it as an AES key to decrypt the rest of the data.

![How decryption works](/data/decryption.png)


# How to install it

    pip install ssh-crypt

# How to use it in python scripts

To decrypt passwords

```python
from ssh_crypt import E

super_secret_password = str(E('{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5'))
```

To encrypt passwords

```python
from ssh_crypt import encrypt

encrypted_password = encrypt('super_secret_password')
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

# Get JSON from JSONC file with encrypted passwords

```bash
    cat test.json
    {
        "tst": 1, // Some number
        "aa": {
            /*
            "bb": [1,2,3],
            "ee": "bbb",
            */
            "password": E"{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5"
        },
        // Some comment
        "cc": [32,21,10],
        "ee": "bbb"
    }
    ssh-crypt -i test.json -t jsonc
    {
        "tst": 1,     "aa": {

            "password": "testpassword"
        },
            "cc": [32,21,10],
        "ee": "bbb"
    }
```

# FIFO mode

In some applications, it is required that the decrypted file be accessible, for example in k9s, which executes kubectl with a parameter
pointing to the configuration file. For this, the fifo mode is suitable, in which ssh_crypt will run in the background and decrypt the file
as it is accessed, while the decrypted file will never touch the disk.

```bash
ENC_FILENAME="/home/user/.kube/kctl.enc"
DEC_FILENAME="/home/user/.kube/kctl"

# Remove FIFO file if it exists
rm $DEC_FILENAME

# To terminate the background process when the script exits
trap 'kill $(jobs -p)' EXIT

# Create a FIFO file to decrypt the file on the fly
ssh-crypt -f -t jsonc -d -i $ENC_FILENAME -o $DEC_FILENAME > /dev/null 2>&1 &

k9s --kubeconfig $DEC_FILENAME
```

# Using SSH-Agent Forwarding

This module also allows you to use scripts with encrypted passwords on remote hosts by connecting to them via ssh.
This can be done by using the ssh-agent to forward your ssh key to the remote host, allowing you to decrypt
the passwords within your scripts on the remote host.

    ssh -A user@somehost

"-A" parameter enables SSH-Agent forwarding.
**Beware!** never use this technique if you don't fully trust remote host
as someone who has enough permissions on remote host may use your ssh agent for bad purpose


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

Pick key from ssh-agent keys list by its fingerprint

    ssh-add -l -E md5
    2048 MD5:12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34 Public key for PIV Authentication (RSA)

Examples:

    ssh-crypt -e -s 'testpassword' --key '12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34'
    ssh-crypt -d -s '{V|B;*R$Ep:HtO~*;QAd?yR#b?V9~a34?!!sxqQT%{!x)bNby^5' -k '12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34'


-t, --type

Set type of input data, for instance it may replace encrypted passwords inside JSONC file returning JSON

Example:

    ssh-crypt -i test.json -t jsonc

-f, --fifomode

Enable FIFO mode, in which the program will decrypt the input data and send it to a special file when accessed


# Bugs

See github issues: https://github.com/Sets88/ssh-crypt/issues
