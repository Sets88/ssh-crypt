import os
from setuptools import setup, find_packages


def get_requirements():
    basedir = os.path.dirname(__file__)
    try:
        with open(os.path.join(basedir, 'requirements.txt')) as f:
            return f.readlines()
    except FileNotFoundError:
        raise RuntimeError('No requirements info found.')


setup(
    name='ssh-crypt',
    version='1.1.10',
    license='BSD',
    author='Maxim Nikitenko',
    author_email='iam@sets88.com',
    packages=find_packages(),
    description='ssh-crypt is a tool to encrypt/decrypt data using your ssh key from ssh-agent',\
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=get_requirements(),
    python_requires='>=3.5',
    url="https://github.com/Sets88/ssh-crypt",
    entry_points={
        'console_scripts': [
            'ssh-crypt = ssh_crypt:main',
        ]
    }
)
