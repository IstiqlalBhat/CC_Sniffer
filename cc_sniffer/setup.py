from setuptools import setup, find_packages

setup(
    name="cc_sniffer",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "cc-sniffer=cc_sniffer.sniffer:main"
        ]
    },
    install_requires=[
        "scapy", "PyYAML", "prometheus-client"
    ],
)
