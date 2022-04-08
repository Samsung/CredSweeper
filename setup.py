import setuptools

with open("README.md", "r", encoding="utf8") as fh:
    long_description = fh.read()

install_requires = [
    "GitPython",
    "google_auth_oauthlib",
    "PyYAML",
    "regex<2022.3.2",
    "requests",
    "typing_extensions",
    "whatthepatch"
]

ml_requires = [
    "numpy",
    "scikit-learn",
    "onnxruntime"
]

setuptools.setup(
    name="credsweeper",
    version="1.2.1",
    description="Credential Sweeper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(include=("credsweeper*", )),
    package_data={
        "credsweeper": [
            "common/keyword_checklist.txt",
            "ml_model/char_to_index.pkl",
            "ml_model/ml_model.onnx",
            "ml_model/model_config.json",
            "secret/config.json",
            "secret/log.yaml",
            "rules/config.yaml"
        ],
    },
    python_requires=">=3.7",
    install_requires=install_requires,
    ml_requires=ml_requires,
    extras_require={
        "ml": ml_requires
    },
    include_package_data=True,
    url="https://github.com/Samsung/CredSweeper",
    project_urls={
        "Bug Tracker": "https://github.com/Samsung/CredSweeper/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance"
    ],
)
