import setuptools

with open("README.md", "r", encoding="utf8") as fh:
    long_description = fh.read()

install_requires = [
    "beautifulsoup4>=4.11.0",  # the lowest version with XMLParsedAsHTMLWarning
    "GitPython",  #
    "google_auth_oauthlib",  #
    "humanfriendly",  #
    "lxml",  #
    "oauthlib",  #
    "openpyxl",  #
    "pandas",  #
    "password-strength",  #
    "pdfminer.six",  #
    "PyYAML",  #
    "requests",  #
    "scipy",  #
    "schwifty",  #
    "typing_extensions",  #
    "whatthepatch",  #
    "numpy",  #
    "scikit-learn",  #
    "onnxruntime",  #
    "python-dateutil",  #
]

setuptools.setup(
    name="credsweeper",
    description="Credential Sweeper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(include=("credsweeper*",)),
    package_data={
        "credsweeper": [
            "py.typed",  #
            "common/keyword_checklist.txt",  #
            "common/morpheme_checklist.txt",  #
            "ml_model/ml_model.onnx",  #
            "ml_model/model_config.json",  #
            "secret/config.json",  #
            "secret/log.yaml",  #
            "rules/config.yaml"  #
        ],
    },
    python_requires=">=3.8",
    install_requires=install_requires,
    include_package_data=True,
    url="https://github.com/Samsung/CredSweeper",
    project_urls={
        "Bug Tracker": "https://github.com/Samsung/CredSweeper/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",  #
        "Programming Language :: Python :: 3 :: Only",  #
        "Programming Language :: Python :: 3.8",  #
        "Programming Language :: Python :: 3.9",  #
        "Programming Language :: Python :: 3.10",  #
        "Programming Language :: Python :: 3.11",  #
        "License :: OSI Approved :: MIT License",  #
        "Operating System :: OS Independent",  #
        "Topic :: Security",  #
        "Topic :: Software Development :: Quality Assurance"  #
    ],
    entry_points={
        "console_scripts": [
            "credsweeper=credsweeper.__main__:main",  #
        ],
    },
)  # yapf: disable
