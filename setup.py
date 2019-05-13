from distutils.core import setup
from setuptools import find_packages

setup(name='tezos-hd-util',
      version='0.0.5',
      packages=find_packages(),
      install_requires=['chainside-btcpy-multi==0.2.77', 'pyblake2==1.1.2', 'secp256k1new==0.13.2'],
      description='Python tool for for tezos hd generation',
      author='Oskar Hladky',
      author_email='oskyks1@gmail.com',
      url='https://github.com/oskyk/tezos-hd-util',
      download_url='https://github.com/oskyk/tezos-hd-util/archive/1.0.4.tar.gz',
      python_requires='>=3',
      keywords=['tezos', 'hd', 'address'],
      classifiers=[
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.6',
      ],
)
