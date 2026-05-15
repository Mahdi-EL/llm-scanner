from setuptools import setup, find_packages

setup(
    name            ="llmscanner",
    version         ="2.0.0",
    author          ="Mahdi EL",
    description     ="The Burp Suite for AI Applications",
    long_description=open("../README.md").read(),
    packages        =find_packages(),
    python_requires =">=3.10",
    install_requires=[
        "groq>=0.4.0",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "reportlab>=4.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
