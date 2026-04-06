# 密码算法验证项目

本项目用于验证解压得到的密码算法测试向量的正确性，优先使用GmSSL国密算法库进行验证。

## 🚀 项目状态

- ✅ Git仓库初始化完成
- 🔧 GmSSL编译中...
- 📋 项目框架搭建完成
- 🔄 验证架构模块化重构完成

## 📁 项目结构

```
algorithm/
├── algorithm/                  # 原始测试向量（来自算法包，只读）
│   ├── SM4/                   # SM4算法测试向量
│   ├── AES/                   # AES算法测试向量  
│   ├── SHA2/                  # SHA2算法测试向量
│   └── ...                   # 其他算法
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
├── scripts/                   # 脚本目录
├── config/                    # 配置文件
├── docs/                      # 文档
├── requirements.txt           # Python依赖
├── setup.py                   # 安装脚本
├── sm4_validator.py           # 原始SM4验证脚本（将被迁移）
├── README.md                  # 项目说明
└── run_validation.py          # 主运行脚本
```

## ✅ 已完成的工作

- ✅ SM4 ECB加密验证通过（5个测试用例）- 使用cryptography库
- ✅ 项目模块化框架搭建
- ✅ 测试向量解析器实现
- ✅ Git本地仓库初始化
- 🔄 GmSSL编译安装进行中...

## 📋 待办事项

### 第一阶段：基础框架
1. [x] 项目结构设计
2. [x] 核心模块开发
3. [ ] GmSSL编译安装完成
4. [ ] GmSSL Python包装器实现

### 第二阶段：SM4算法验证
1. [x] SM4 ECB加密验证
2. [ ] SM4 ECB解密验证
3. [ ] SM4 CBC加密验证（GmSSL版）
4. [ ] SM4 CBC解密验证
5. [ ] SM4其他模式验证

### 第三阶段：扩展验证
1. [ ] AES算法验证
2. [ ] SHA2算法验证
3. [ ] 其他国密算法验证（SM1-SM4, SM7, SM9, SSF33, ZUC等）

## 🛠️ 使用方法

### 环境准备
```bash
# 安装Python依赖
pip3 install -r requirements.txt

# 安装GmSSL（正在编译）
# 自动安装脚本会处理
```

### 验证SM4算法（旧版本）
```bash
python3 sm4_validator.py
```

### 验证全部算法（新架构）
```bash
python3 run_validation.py --algorithm sm4
python3 run_validation.py --all
```

## 🔌 依赖

- **Python 3.8+**
- **GmSSL库**（国密算法参考实现，正在编译）
- 可选依赖：`chardet`, `click`, `colorama`（已在requirements.txt中）

## 📊 测试向量

测试向量来自算法包的`algorithm/`目录，包含多种密码算法的标准测试用例，使用GBK编码。

## 🤝 贡献指南

1. Fork本仓库
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建Pull Request

## 📄 许可证

MIT License