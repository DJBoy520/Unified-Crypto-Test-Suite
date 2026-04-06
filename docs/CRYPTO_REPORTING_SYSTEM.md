# 统一加密算法测试报告生成系统

## 📖 概述

这是一个统一的、可扩展的测试报告生成系统，支持SM2/SM3/SM4/国际算法的测试报告生成。系统采用面向对象设计，易于扩展和维护。

## ✨ 主要特性

- **统一架构**: 基于抽象基类设计，支持多种加密算法
- **精确时间戳**: 报告文件名包含精确到秒的时间戳
- **双格式输出**: 同时生成JSON详细报告和TXT摘要报告
- **丰富内容**: 包含元数据、环境信息、测试摘要、详细结果、失败分析、性能指标、合规性检查和改进建议
- **易于扩展**: 支持未来添加新的加密算法
- **配置化**: 支持配置文件定义报告模板
- **多数据源**: 支持从多种数据源读取测试结果

## 🏗️ 系统架构

```
BaseCryptoReporter (抽象基类)
├── SM2Reporter (SM2专用)
├── SM3Reporter (SM3专用)
├── SM4Reporter (SM4专用)
└── AESReporter (AES专用，可扩展)

MultiAlgorithmReporter (多算法合并报告生成器)
```

## 📦 安装和使用

### 1. 基本使用

```python
from src.crypto_test_reporter import SM2Reporter

# 创建报告生成器
reporter = SM2Reporter()

# 生成报告
test_results = {
    "total_tests": 40,
    "passed": 36,
    "failed": 4,
    "details": [...]
}
report_paths = reporter.save_reports(test_results, "./reports")
```

### 2. 便捷函数使用

```python
from src.crypto_test_reporter import generate_sm2_report

# 快速生成SM2报告
paths = generate_sm2_report(test_results, "./reports")
```

### 3. 多算法报告生成

```python
from src.crypto_test_reporter import MultiAlgorithmReporter

# 准备多个算法的测试结果
all_results = {
    "SM2": sm2_results,
    "SM3": sm3_results,
    "SM4": sm4_results
}

# 生成合并报告
multi_reporter = MultiAlgorithmReporter()
combined_paths = multi_reporter.save_combined_reports(all_results, "./reports")
```

## 📋 报告内容结构

### JSON报告结构

```json
{
  "test_report": {
    "metadata": {
      "report_id": "SM2_TEST_20240325_143052",
      "algorithm": "SM2",
      "algorithm_description": "SM2椭圆曲线公钥密码算法",
      "test_type": "FULL",
      "generation_time": "2024-03-25T14:30:52.123456",
      "test_duration_seconds": 45.67,
      "standard": "GM/T 0003-2012"
    },
    "environment": {
      "python_version": "3.9.7",
      "platform": "Linux-5.4.0-74-generic-x86_64-with-glibc2.31",
      "os": "Linux 5.4.0-74-generic",
      "architecture": "64bit",
      "processor": "x86_64",
      "cpu_count": 8,
      "memory_total_gb": 15.6,
      "memory_available_gb": 12.3
    },
    "summary": {
      "total_tests": 40,
      "passed": 36,
      "failed": 4,
      "skipped": 0,
      "error": 0,
      "pass_rate_percent": 90.0,
      "test_duration_seconds": 45.67
    },
    "algorithm_specific": {
      "test_categories": [...],
      "performance_metrics": {...},
      "algorithm_features": [...]
    },
    "detailed_results": [...],
    "failure_analysis": {...},
    "performance_metrics": {...},
    "compliance": {...},
    "recommendations": [...]
  }
}
```

### TXT报告示例

```
================================================================================
🇨🇳 SM2椭圆曲线公钥密码算法测试报告
================================================================================
报告ID: SM2_TEST_20240325_143052
生成时间: 2024-03-25 14:30:52

📊 测试摘要
--------------------------------------------------------------------------------
总测试用例: 40
通过: 36
失败: 4
跳过: 0
错误: 0
通过率: 90.00%

🔧 SM2算法测试分类
--------------------------------------------------------------------------------
• 基本功能验证: 6/6
• 密钥对验证: 3/3
• 加密计算验证: 45/50
• 解密计算验证: 48/50
• 签名计算验证: 40/47

⚡ 性能指标
--------------------------------------------------------------------------------
加密速度: N/A KB/s
解密速度: N/A KB/s
签名速度: N/A ops/s
验签速度: N/A ops/s

🎯 合规性检查
--------------------------------------------------------------------------------
国密标准: GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3), GB/T 32918.1-2016
测试覆盖率: 90.00%
合规性状态: 部分符合

💡 改进建议
--------------------------------------------------------------------------------
⚠️ 测试通过率较低，建议检查算法实现
📊 建议定期运行完整测试套件以监控算法稳定性
🔧 建议维护详细的测试日志以便问题追踪
📈 建议添加性能基准测试以监控算法效率变化

================================================================================
```

## 🔧 扩展开发

### 添加新的算法支持

1. 创建新的报告生成器类：

```python
from src.crypto_test_reporter import BaseCryptoReporter

class AESReporter(BaseCryptoReporter):
    """AES算法专用报告生成器"""

    def __init__(self):
        super().__init__("AES", "FULL")

    def generate_json_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        # 实现AES专用JSON报告生成
        pass

    def generate_txt_summary(self, test_results: Dict[str, Any]) -> str:
        # 实现AES专用TXT摘要生成
        pass
```

2. 在MultiAlgorithmReporter中注册新算法：

```python
self.algorithm_reporters["AES"] = AESReporter()
```

### 使用配置文件

系统支持通过配置文件自定义报告模板：

```ini
[sm2]
algorithm_name = SM2椭圆曲线公钥密码算法
standard = GM/T 0003-2012
performance_metrics = encryption_speed_kbps,decryption_speed_kbps
```

## 🧪 测试和演示

运行演示脚本：

```bash
python3 demo_crypto_reporting.py
```

这将生成各种示例报告，展示系统的功能。

## 🔗 集成现有代码

### 与sm2_unified_test_simple.py的集成

系统已集成到现有的SM2测试框架中：

```python
# 在sm2_unified_test_simple.py中自动使用新报告系统
tester = SM2UnifiedTestSimple()
results = tester.run_all_tests()
tester.save_results("./reports")  # 自动使用新报告系统
```

### 手动集成其他算法

```python
# 为其他算法添加报告生成功能
from src.crypto_test_reporter import generate_multi_algorithm_report

all_results = {
    "SM2": sm2_test_results,
    "SM3": sm3_test_results,
    "SM4": sm4_test_results,
    "AES": aes_test_results
}

# 生成综合报告
generate_multi_algorithm_report(all_results, "./comprehensive_reports")
```

## 📊 性能优化

- **大报告处理**: 支持分块处理大报告，避免内存溢出
- **超时保护**: 报告生成过程有超时限制
- **异步处理**: 支持后台生成大型报告
- **缓存机制**: 重复数据缓存，提高生成效率

## 🛠️ 配置选项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| output_format | json,txt | 输出格式 |
| max_report_size_mb | 50 | 最大报告大小 |
| timeout_seconds | 300 | 生成超时时间 |
| enable_performance_metrics | true | 启用性能指标 |
| enable_environment_info | true | 启用环境信息 |

## 📝 注意事项

1. **时间戳精度**: 报告文件名包含精确到秒的时间戳，确保唯一性
2. **编码处理**: 所有报告使用UTF-8编码，支持中文字符
3. **错误处理**: 完善的异常处理机制，确保报告生成过程的稳定性
4. **向后兼容**: 保持与现有测试框架的兼容性
5. **扩展性**: 设计时考虑了未来算法扩展的需求

## 🤝 贡献

欢迎提交Issue和Pull Request来改进系统。

## 📄 许可证

本项目采用MIT许可证。