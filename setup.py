import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent

README = (HERE / "README.md").read_text()

setup(
    name="muid",
    version="0.4.5",
    description="Memorable Unique Identifier",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/microprediction/muid",
    author="microprediction",
    author_email="info@microprediction.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    packages=["muid"],
    test_suite='pytest',
    tests_require=['pytest'],
    include_package_data=True,
    install_requires=["pathlib","contexttimer","ring"],
    entry_points={
        "console_scripts": [
            "muid=muid.__main__:main",
        ]
     },
     )
