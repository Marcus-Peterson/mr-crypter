from setuptools import setup, find_packages

setup(
    name="safestring",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'cryptography>=43.0.0',
        'rich>=13.0.0',
    ],
) 