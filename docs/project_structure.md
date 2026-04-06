# 密码算法验证项目结构

```
algorithm/
├── algorithm/                  # 原始测试向量（只读）
│   ├── SM4/
│   ├── AES/
│   ├── SHA2/
│   └── ...
├── src/                       # 源码目录
│   ├── core/                  # 核心模块
│   │   ├── validator.py       # 验证器基类
│   │   ├── parser.py          # 测试向量解析器
│   │   └── gmssl_wrapper.py   # GmSSL包装器
│   ├── algorithms/            # 算法实现
│   │   ├── sm4_validator.py   # SM4验证器
│   │   ├── aes_validator.py   # AES验证器
│   │   ├── sha2_validator.py  # SHA2验证器
│   │   └── __init__.py
│   ├── utils/                 # 工具函数
│   │   ├── file_utils.py
│   │   ├── crypto_utils.py
│   │   └── __init__.py
│   └── __init__.py
├── tests/                     # 测试文件
│   ├── test_sm4.py
│   ├── test_aes.py
│   ├── __init__.py
│   └── test_data/             # 测试数据
│       ├── sm4_vectors.json
│       └── ...
├── scripts/                   # 脚本目录
│   ├── validate_sm4.py        # SM4验证入口
│   ├── validate_all.py        # 全算法验证
│   └── install_gmssl.py       # GmSSL安装脚本
├── config/                    # 配置文件
│   ├── settings.py
│   └── algorithm_config.json
├── docs/                      # 文档
│   ├── usage.md
│   └── api-reference.md
├── requirements.txt           # Python依赖
├── setup.py                   # 安装脚本
├── README.md                  # 项目说明
└── run_validation.py          # 主运行脚本
```

## 工作流程

1. **配置环境**：安装GmSSL、Python依赖
2. **解析测试向量**：读取算法目录下的标准测试文件
3. **调用算法**：通过GmSSL包装器调用对应算法实现
4. **验证结果**：比较预期输出与实际输出
5. **生成报告**：输出验证结果和错误详情