from setuptools import setup, find_packages

setup(
    name="kartika-cds",
    version="2.4.0",
    description="KARTIKA-CDS: Unidirectional Cross-Domain Security Gateway",
    author="Rafstar14",
    packages=find_packages(),
    py_modules=["run_dev", "cli"],
    install_requires=[
        "Flask>=3.0",
        "cryptography>=41.0",
        "yara-python>=4.5",
        "pyclamd>=0.4.0",
        "pytest>=8.0",
    ],
    entry_points={
        "console_scripts": [
            "kartika=run_dev:main",
        ],
    },
    python_requires=">=3.10",
)
