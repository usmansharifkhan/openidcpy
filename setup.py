from setuptools import setup

setup(
    name="openidcpy",
    version='0.1',
    description='A package that implements the Relying Party Authorization Code Flow for OpenId Connect',
    license='Apache 2.0',
    author='Usman Shahid',
    author_email='usman.shahid@intechww.com',
    url='https://github.com/intech-iiot/openidcpy',
    tests_require=['mock==2.0.0'],
    install_requires=[
      'requests==2.20.0',
      'python-jose==3.0.1'

    ]
)
