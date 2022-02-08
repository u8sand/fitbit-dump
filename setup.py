import pathlib
from setuptools import setup, find_packages

setup(
  name='fitbit-dump',
  version=open(pathlib.Path('fitbit_dump') / 'VERSION', 'r').read(),
  url='https://github.com/u8sand/fitbit-dump',
  author='Daniel J. B. Clarke',
  author_email='u8sand@gmail.com',
  long_description=open('README.md', 'r').read(),
  install_requires=list(map(str.strip, open('requirements.txt', 'r').readlines())),
  packages=find_packages(),
  entry_points={
    'console_scripts': ['fitbit-dump=fitbit_dump.__main__:cli'],
  }
)
