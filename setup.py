"""Python setup.py for cos_registration_agent package"""
import io
import os
from setuptools import find_packages, setup


def read(*paths, **kwargs):
    """Read the contents of a text file safely.
    >>> read("cos_registration_agent", "VERSION")
    '0.1.0'
    >>> read("README.md")
    ...
    """

    content = ""
    with io.open(
        os.path.join(os.path.dirname(__file__), *paths),
        encoding=kwargs.get("encoding", "utf8"),
    ) as open_file:
        content = open_file.read().strip()
    return content


def read_requirements(path):
    return [
        line.strip()
        for line in read(path).split("\n")
        if not line.startswith(('"', "#", "-", "git+"))
    ]


setup(
    name="cos_registration_agent",
    version=read("cos_registration_agent", "VERSION"),
    description="Awesome cos_registration_agent created by ubuntu-robotics",
    url="https://github.com/ubuntu-robotics/cos-registration-agent/",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="ubuntu-robotics",
    packages=find_packages(exclude=["tests", ".github"]),
    install_requires=read_requirements("requirements.txt"),
    entry_points={
        "console_scripts": ["cos_registration_agent = cos_registration_agent.__main__:main"]
    },
    extras_require={"test": read_requirements("requirements-test.txt")},
)
