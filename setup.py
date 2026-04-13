import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

version = {}
with open("valhallaAPI/version.py", "r") as fh:
    exec(fh.read(), version)

setuptools.setup(
    name="valhallaapi",
    version=version["__version__"],
    author="Nextron",
    author_email="florian.roth@nextron-systems.com",
    description="Valhalla API Client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NextronSystems/valhallaAPI",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'packaging',
        'requests',
        'configparser',
    ],
    python_requires='~=3.5',
    entry_points={
        'console_scripts': [
            'valhalla-cli = valhallaAPI.valhalla_cli:main',
        ],
    },
)
