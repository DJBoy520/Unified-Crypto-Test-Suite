# 测试报告生成器

这个目录包含测试报告生成相关的程序和文档。

## 文件说明

- `test_report_generator.py`: 主要的测试报告生成器程序
- `SM4_TEST_README.md`: SM4测试相关说明文档
- `test_report_summary.md`: 测试报告总结文档

## 使用方法

### 生成测试报告

```bash
# 从项目根目录运行
python3 src/reports/test_report_generator.py -i results/crypto_test_suite_results.json -o results

# 指定输出格式
python3 src/reports/test_report_generator.py -i results/crypto_test_suite_results.json -f html -o results
```

### 参数说明

- `-i, --input`: 测试结果JSON文件路径 (必需)
- `-o, --output`: 输出目录 (可选，默认与输入文件同目录)
- `-f, --format`: 报告格式
  - `txt`: 文本格式
  - `html`: HTML格式
  - `md`: Markdown格式
  - `all`: 全部格式 (默认)

### 输出文件

运行后会在输出目录生成以下文件：
- `*_report.txt`: 文本格式报告
- `*_report.html`: HTML格式报告
- `*_report.md`: Markdown格式报告

## 集成到测试套件

报告生成器可以独立运行，也可以集成到自动化测试流程中。