import sys

import setuptools

with open("README.md", "r", encoding="utf8") as fh:
    long_description = fh.read()

onnxruntime_pkg = "onnxruntime"
if "darwin" == sys.platform and 9 == sys.version_info.minor:
    # workaround for https://github.com/microsoft/onnxruntime/issues/14663
    # onnxruntime v1.14.0 for macos with Python3.9.16 has package issue (have (arm64), need (x86_64)))
    onnxruntime_pkg += "<=1.13.1"

install_requires = [
    "beautifulsoup4",  #
    "GitPython",  #
    "google_auth_oauthlib",  #
    "humanfriendly",  #
    "lxml",  #
    "oauthlib",  #
    "openpyxl",  #
    "pandas",  #
    "PyYAML",  #
    "regex",  #
    "requests",  #
    "scipy",  #
    "typing_extensions",  #
    "whatthepatch",  #
    "numpy",  #
    "scikit-learn",  #
    onnxruntime_pkg  #
]

setuptools.setup(
    name="credsweeper",
    description="Credential Sweeper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(include=("credsweeper*", )),
    package_data={
        "credsweeper": [
            "py.typed",  #
            "common/keyword_checklist.txt",  #
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
)
