from setuptools import find_packages, setup

with open("web3login/version.txt") as ifp:
    VERSION = ifp.read().strip()

long_description = ""
with open("README.md") as ifp:
    long_description = ifp.read()

setup(
    name="web3login",
    version=VERSION,
    packages=find_packages(),
    install_requires=[
        "eip712",
        "eth-typing>=2.3.0",
        "web3>=5.30.0",
    ],
    extras_require={
        "dev": ["black", "mypy", "isort"],
        "distribute": ["setuptools", "twine", "wheel"],
        "fastapi": ["fastapi"],
    },
    description="Moonstream: Open source Web3 authorization library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Moonstream",
    author_email="engineering@moonstream.to",
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries",
    ],
    url="https://github.com/bugout-dev/web3login",
    package_data={"web3login": ["py.typed"]},
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "web3login=web3login.cli:main",
        ]
    },
)
