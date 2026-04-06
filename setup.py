#!/usr/bin/env python3
"""
密码算法验证项目安装脚本
"""

from setuptools import setup, find_packages
import os

# 读取README内容
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# 读取requirements.txt
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="crypto-algorithm-validator",
    version="0.1.0",
    description="密码算法标准化测试向量验证工具",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Crypto Validator",
    author_email="validator@openclaw.local",
    url="https://github.com/user/crypto-validator",
    packages=find_packages(include=['src', 'src.*']),
    package_dir={'': '.'},
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    entry_points={
        "console_scripts": [
            "validate-crypto=scripts.validate_all:main",
            "validate-sm4=scripts.validate_sm4:main",
        ]
    },
    scripts=[
        'run_validation.py',
    ],
    keywords="cryptography sm4 aes sha2 gmssl validation test-vectors",
    project_urls={
        "Bug Reports": "https://github.com/user/crypto-validator/issues",
        "Source": "https://github.com/user/crypto-validator",
    },
)