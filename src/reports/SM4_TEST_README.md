# SM4算法统一测试程序

## 概述

`sm4_unified_test.py` 是一个统一的SM4算法测试程序，能够解析 `algorithm/SM4/` 目录下的所有测试向量文件，并使用Python cryptography库进行验证。

## 功能特性

- **自动解析**: 支持GBK编码检测，自动解析各种格式的SM4测试向量
- **多模式支持**: 支持ECB, CBC, OFB, CFB, CTR等标准模式
- **智能跳过**: 自动跳过cryptography库不支持的模式（如XTS, GCM等）
- **详细报告**: 生成JSON格式的详细结果和文本摘要报告
- **命令行友好**: 支持自定义输入输出目录

## 使用方法

```bash
# 基本使用（使用默认目录）
python3 sm4_unified_test.py

# 指定测试向量目录
python3 sm4_unified_test.py -i ./algorithm/SM4

# 指定输出目录
python3 sm4_unified_test.py -o ./test_results

# 查看帮助
python3 sm4_unified_test.py --help
```

## 输出文件

- `sm4_test_results.json`: 详细的测试结果，包括每个测试用例的通过/失败状态
- `sm4_test_summary.txt`: 统计摘要，按文件和模式分类显示通过率

## 支持的测试向量格式

程序能够解析以下格式的测试文件：

```
密钥= 0123456789ABCDEF...
明文= FEDCBA9876543210...
密文= ExpectedCipherText...
IV = InitializationVector... (CBC/OFB/CFB/CTR模式)
```

## 测试结果说明

- **通过**: 测试用例完全匹配期望结果
- **失败**: 测试用例结果不匹配或存在错误
- **跳过**: 模式暂不支持（如XTS需要特殊密钥处理，GCM需要认证标签支持）

## 当前支持状态

- ✅ ECB, CBC, OFB, CFB, CTR: 基础实现
- ❌ XTS, GCM, CCM, HCTR: cryptography库限制，暂不支持

## 依赖要求

- Python 3.8+
- cryptography库: `pip install cryptography`