from setuptools import setup, find_packages

setup(
    name="canopen_security_platform",
    version="0.1.0",
    description="CANopen security platform skeleton",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "python-can",
        "canopen",
    ],
    entry_points={
        "console_scripts": [
            "cansec=canopen_security_platform.cli.main:main",
        ],
    },
)
