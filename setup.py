from setuptools import setup

setup(
    name="openidcpy",
    version='0.1',
    description='A package that implements the RP auth flow for OpenId Connect',
    license='Apache 2.0',
    author='Usman Shahid',
    author_email='usman.shahid@intechww.com',
    tests_require=['mock==2.0.0'],
    install_requires=[
      'requests==2.19.1',
      'jwcrypto==0.6.0',

    ]
)