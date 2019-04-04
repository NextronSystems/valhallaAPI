import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="valhallaAPI",
    version="0.2.5",
    author="Nextron",
    author_email="venom14@gmail.com",
    description="Valhalla API Client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nextron/valhallaAPI",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'packaging',
        'requests',
    ],
    python_requires='~=3.5',
    scripts=[
        'valhalla-cli',
    ]
)
