import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = [
    "GitPython",
    "google_auth_oauthlib",
    "PyYAML",
    "regex",
    "requests"
]

ml_requires = [
    "numpy",
    "scikit-learn",
    "tensorflow>=2.3.0, <2.6.0"
]

setuptools.setup(
    name="CredSweeper",
    version="1.0.0",
    description="Credential Sweeper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(include=("credsweeper*", )),
    package_data={
        "credsweeper": [
            "common/keyword_checklist.txt",
            "ml_model/char_to_index.pkl",
            "ml_model/ml_model.h5",
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
)
