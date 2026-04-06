#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4测试系统快速验证脚本
验证所有核心功能是否正常工作
"""

import sys
from pathlib import Path

# 添加项目根目录
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """测试所有模块导入"""
    print("=" * 80)
    print("🧪 测试1: 模块导入")
    print("=" * 80)
    
    tests = [
        ("sm4_vector_parser", "from src.sm4.sm4_vector_parser import SM4VectorParser"),
        ("sm4_multimode", "from src.sm4.sm4_multimode import SM4"),
        ("sm4_aead", "from src.sm4.sm4_aead import SM4_AEAD"),
        ("sm4_vector_validator", "from src.sm4.sm4_vector_validator import SM4VectorValidator"),
        ("sm4_reporter", "from src.crypto_test_reporter import SM4Reporter"),
    ]
    
    passed = 0
    for name, import_stmt in tests:
        try:
            exec(import_stmt)
            print(f"✓ {name:20} - OK")
            passed += 1
        except Exception as e:
            print(f"✗ {name:20} - FAIL: {e}")
    
    print(f"\n结果: {passed}/{len(tests)} 通过\n")
    return passed == len(tests)


def test_vector_parsing():
    """测试向量解析"""
    print("=" * 80)
    print("🧪 测试2: 向量解析")
    print("=" * 80)
    
    from src.sm4.sm4_vector_parser import parse_sm4_vector_file
    
    file_path = "./algorithm/SM4/sm4_cfb_enc_fb128bit.txt"
    
    try:
        vectors = parse_sm4_vector_file(file_path)
        
        if vectors and '_error' not in vectors[0]:
            print(f"✓ 成功解析 {len(vectors)} 个向量")
            
            first = vectors[0]
            print(f"  模式: {first.get('mode')}")
            print(f"  字段: {[k for k in first.keys() if not k.startswith('_')]}")
            print(f"  密钥: {first.get('key', '')[:32]}...")
            return True
        else:
            error = vectors[0].get('_error', 'Unknown error')
            print(f"✗ 解析失败: {error}")
            return False
    
    except Exception as e:
        print(f"✗ 异常: {e}")
        return False


def test_encryption():
    """测试加密功能"""
    print("\n" + "=" * 80)
    print("🧪 测试3: 加密/解密功能")
    print("=" * 80)
    
    from src.sm4.sm4_multimode import SM4
    
    try:
        key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
        plaintext = b"Hello SM4 World!"
        
        cipher = SM4(key)
        
        # 测试ECB
        try:
            ciphertext_ecb = cipher.encrypt_ecb(plaintext, padding=False)
            recovered_ecb = cipher.decrypt_ecb(ciphertext_ecb, padding=False)
            
            if recovered_ecb == plaintext:
                print(f"✓ ECB模式 - OK")
            else:
                print(f"✗ ECB模式 - 解密不匹配")
                return False
        except Exception as e:
            print(f"✗ ECB模式 - {e}")
            return False
        
        # 测试CBC
        try:
            iv = b"1234567890123456"
            ciphertext_cbc = cipher.encrypt_cbc(plaintext, iv, padding=False)
            recovered_cbc = cipher.decrypt_cbc(ciphertext_cbc, iv, padding=False)
            
            if recovered_cbc == plaintext:
                print(f"✓ CBC模式 - OK")
            else:
                print(f"✗ CBC模式 - 解密不匹配")
                return False
        except Exception as e:
            print(f"✗ CBC模式 - {e}")
            return False
        
        # 测试CFB
        try:
            ciphertext_cfb = cipher.encrypt_cfb(plaintext, iv, segment_size=128)
            recovered_cfb = cipher.decrypt_cfb(ciphertext_cfb, iv, segment_size=128)
            
            if recovered_cfb == plaintext:
                print(f"✓ CFB模式 - OK")
            else:
                print(f"✗ CFB模式 - 解密不匹配")
                return False
        except Exception as e:
            print(f"✗ CFB模式 - {e}")
            return False
        
        # 测试OFB
        try:
            ciphertext_ofb = cipher.encrypt_ofb(plaintext, iv)
            recovered_ofb = cipher.decrypt_ofb(ciphertext_ofb, iv)
            
            if recovered_ofb == plaintext:
                print(f"✓ OFB模式 - OK")
            else:
                print(f"✗ OFB模式 - 解密不匹配")
                return False
        except Exception as e:
            print(f"✗ OFB模式 - {e}")
            return False
        
        # 测试CTR
        try:
            ciphertext_ctr = cipher.encrypt_ctr(plaintext, iv)
            recovered_ctr = cipher.decrypt_ctr(ciphertext_ctr, iv)
            
            if recovered_ctr == plaintext:
                print(f"✓ CTR模式 - OK")
            else:
                print(f"✗ CTR模式 - 解密不匹配")
                return False
        except Exception as e:
            print(f"✗ CTR模式 - {e}")
            return False
        
        return True
    
    except Exception as e:
        print(f"✗ 异常: {e}")
        return False


def test_validation():
    """测试向量验证"""
    print("\n" + "=" * 80)
    print("🧪 测试4: 向量验证")
    print("=" * 80)
    
    from src.sm4.sm4_vector_parser import parse_sm4_vector_file
    from src.sm4.sm4_vector_validator import SM4VectorValidator
    
    try:
        file_path = "./algorithm/SM4/sm4_cfb_enc_fb128bit.txt"
        vectors = parse_sm4_vector_file(file_path)
        
        if not vectors or '_error' in vectors[0]:
            print("✗ 无法解析向量文件")
            return False
        
        validator = SM4VectorValidator(verbose=False)
        
        # 验证第一个向量
        first_vector = vectors[0]
        mode = first_vector.get('mode')
        
        result = validator.validate_vector(first_vector, mode)
        
        if result.get('passed'):
            print(f"✓ 向量验证 (模式: {mode}) - 通过")
            return True
        else:
            error = result.get('error', 'Unknown error')
            print(f"✗ 向量验证 (模式: {mode}) - 失败: {error}")
            return False
    
    except Exception as e:
        print(f"✗ 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_reporter():
    """测试报告生成"""
    print("\n" + "=" * 80)
    print("🧪 测试5: 报告生成")
    print("=" * 80)
    
    from src.crypto_test_reporter import SM4Reporter
    import tempfile
    import os
    
    try:
        reporter = SM4Reporter()
        
        # 创建模拟测试结果
        test_results = {
            "total_tests": 10,
            "passed": 8,
            "failed": 2,
            "error": 0,
            "details": [
                {"test_name": "ECB-1", "passed": True, "mode": "ECB"},
                {"test_name": "CBC-1", "passed": True, "mode": "CBC"},
                {"test_name": "CFB-1", "passed": False, "mode": "CFB", "error": "Mismatch"},
                {"test_name": "OFB-1", "passed": True, "mode": "OFB"},
                {"test_name": "CTR-1", "passed": True, "mode": "CTR"},
                {"test_name": "GCM-1", "passed": True, "mode": "GCM"},
                {"test_name": "MAC-1", "passed": False, "mode": "MAC", "error": "Tag mismatch"},
                {"test_name": "XTS-1", "passed": True, "mode": "XTS"},
            ]
        }
        
        # 创建临时目录
        with tempfile.TemporaryDirectory() as tmpdir:
            # 生成报告
            report_files = reporter.save_reports(test_results, tmpdir)
            
            # 检查文件是否存在
            json_exists = os.path.exists(report_files['json'])
            txt_exists = os.path.exists(report_files['txt'])
            
            if json_exists and txt_exists:
                print(f"✓ 报告生成成功")
                print(f"  JSON 报告: {report_files['json']}")
                print(f"  TXT 报告: {report_files['txt']}")
                return True
            else:
                print(f"✗ 报告文件不存在")
                print(f"  JSON: {json_exists}, TXT: {txt_exists}")
                return False
    
    except Exception as e:
        print(f"✗ 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """运行所有测试"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "SM4测试系统快速验证".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    results = {
        "模块导入": test_imports(),
        "向量解析": test_vector_parsing(),
        "加密解密": test_encryption(),
        "向量验证": test_validation(),
        "报告生成": test_reporter(),
    }
    
    print("\n" + "=" * 80)
    print("📊 测试总结")
    print("=" * 80)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} - {name}")
    
    print()
    print(f"总体: {passed}/{total} 通过")
    
    if passed == total:
        print("\n✅ 所有测试通过！系统已准备就绪。")
        print("\n快速开始:")
        print("  python3 src/sm4/sm4_comprehensive_test.py")
        return 0
    else:
        print(f"\n❌ 有 {total - passed} 个测试失败。")
        return 1


if __name__ == '__main__':
    sys.exit(main())
