from setuptools import setup

setup(
    name='pxelpher',
    version='0.1dev',
    packages=['pxelpher',],
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    long_description="",

    entry_points={
        'console_scripts': [
            'dhcp_server=pxelpher.server:main',
        ],
    },
)
