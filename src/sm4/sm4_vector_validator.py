#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4测试向量验证模块
根据测试向量验证SM4各模式的正确性
"""

import os
from typing import Dict, List, Any, Optional
from pathlib import Path

from src.sm4.sm4_vector_parser import SM4VectorParser, parse_sm4_vector_file
from src.sm4.sm4_multimode import SM4, sm4_encrypt, sm4_decrypt
from src.sm4.sm4_aead import SM4_AEAD
from src.sm4.sm4_impl import SM4 as SM4Impl


class SM4VectorValidator:
    """SM4测试向量验证器"""
    
    def __init__(self, verbose: bool = True):
        """
        初始化验证器
        
        Args:
            verbose: 是否打印详细信息
        """
        self.verbose = verbose
    
    def _log(self, message: str):
        """记录信息"""
        if self.verbose:
            print(message)
    
    def validate_vector(self, vector: Dict[str, Any], mode: str) -> Dict[str, Any]:
        """
        验证单个测试向量
        
        Args:
            vector: 测试向量（包含key, iv, plaintext, ciphertext等）
            mode: 加密模式
        
        Returns:
            验证结果字典
        """
        result = {
            'passed': False,
            'mode': mode,
            'error': '',
            'expected': {},
            'actual': {}
        }
        
        try:
            # 检查必要字段
            if '_error' in vector:
                result['error'] = f"向量解析错误: {vector['_error']}"
                return result
            
            # 获取密钥
            if 'key' not in vector or 'key_bytes' not in vector:
                result['error'] = "缺少密钥字段"
                return result
            
            key = vector['key_bytes']
            
            # 根据模式处理
            if mode in ['ECB', 'ECB-DECRYPT', 'ECB-ENC']:
                result = self._validate_ecb(vector, result)
            elif mode in ['CBC', 'CBC-DECRYPT', 'CBC-ENC', 'CBC-DEC']:
                result = self._validate_cbc(vector, result)
            elif mode in ['CFB', 'CFB-FB8', 'CFB-FB128', 'CFB-DEC', 'CFB-ENC']:
                result = self._validate_cfb(vector, result)
            elif mode in ['OFB', 'OFB-DEC', 'OFB-ENC']:
                result = self._validate_ofb(vector, result)
            elif mode in ['CTR', 'CTR-DEC', 'CTR-ENC']:
                result = self._validate_ctr(vector, result)
            elif mode in ['GCM', 'GCM-DEC', 'GCM-ENC']:
                result = self._validate_gcm(vector, result)
            elif mode in ['XTS', 'XTS-GB', 'XTS-DEC', 'XTS-ENC']:
                result = self._validate_xts(vector, result)
            elif mode in ['MAC']:
                result = self._validate_mac(vector, result)
            else:
                result['error'] = f"不支持的模式: {mode}"
            
        except Exception as e:
            result['error'] = f"验证异常: {str(e)}"
        
        return result
    
    def _validate_ecb(self, vector: Dict, result: Dict) -> Dict:
        """验证ECB模式"""
        try:
            key = vector['key_bytes']
            cipher = SM4(key)  # 用多模式实现（PKCS#7填充）
            
            # 验证加密
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_ecb(plaintext)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配"
                    return result
                
                # 验证解密
                actual_plaintext = cipher.decrypt_ecb(expected_ciphertext)
                result['actual']['plaintext'] = actual_plaintext.hex().upper()
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
        def _validate_cbc(self, vector: Dict, result: Dict) -> Dict:
        """验证CBC模式"""
        try:
            key = vector['key_bytes']
            
            if 'iv_bytes' not in vector:
                result['error'] = "缺少IV字段"
                return result
            
            iv = vector['iv_bytes']
            cipher = SM4(key)
            
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_cbc(plaintext, iv, padding=False)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配"
                    return result
                
                # 验证解密
                actual_plaintext = cipher.decrypt_cbc(expected_ciphertext, iv, padding=False)
                result['actual']['plaintext'] = actual_plaintext.hex().upper()
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_cfb(self, vector: Dict, result: Dict) -> Dict:
        """验证CFB模式"""
        try:
            key = vector['key_bytes']
            
            if 'iv_bytes' not in vector:
                result['error'] = "缺少IV字段"
                return result
            
            iv = vector['iv_bytes']
            cipher = SM4(key)
            
            # 确定反馈大小（FB8或FB128）
            mode = vector.get('mode', 'CFB')
            if 'FB8' in mode.upper():
                segment_size = 8
            else:
                segment_size = 128
            
            result['mode'] = mode
            
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_cfb(plaintext, iv, segment_size)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配 (FB{segment_size})"
                    return result
                
                # 验证解密
                actual_plaintext = cipher.decrypt_cfb(expected_ciphertext, iv, segment_size)
                result['actual']['plaintext'] = actual_plaintext.hex().upper()
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_ofb(self, vector: Dict, result: Dict) -> Dict:
        """验证OFB模式"""
        try:
            key = vector['key_bytes']
            
            if 'iv_bytes' not in vector:
                result['error'] = "缺少IV字段"
                return result
            
            iv = vector['iv_bytes']
            cipher = SM4(key)
            
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_ofb(plaintext, iv)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配"
                    return result
                
                # 验证解密（OFB加密和解密相同）
                actual_plaintext = cipher.decrypt_ofb(expected_ciphertext, iv)
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_ctr(self, vector: Dict, result: Dict) -> Dict:
        """验证CTR模式"""
        try:
            key = vector['key_bytes']
            
            if 'iv_bytes' not in vector:
                result['error'] = "缺少IV字段"
                return result
            
            iv = vector['iv_bytes']
            cipher = SM4(key)
            
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_ctr(plaintext, iv)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配"
                    return result
                
                # 验证解密（CTR加密和解密相同）
                actual_plaintext = cipher.decrypt_ctr(expected_ciphertext, iv)
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_gcm(self, vector: Dict, result: Dict) -> Dict:
        """验证GCM模式"""
        try:
            key = vector['key_bytes']
            
            if 'iv_bytes' not in vector:
                result['error'] = "缺少IV字段"
                return result
            
            iv = vector['iv_bytes']
            aad = vector.get('add_bytes', b'')
            
            cipher = SM4(key)
            
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                expected_tag = vector.get('tag_bytes', b'')
                
                if not expected_tag:
                    result['error'] = "GCM模式需要tag字段"
                    return result
                
                # 加密
                actual_ciphertext, actual_tag = SM4_AEAD.encrypt_gcm(
                    cipher, plaintext, iv, aad, len(expected_tag)
                )
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['expected']['tag'] = vector.get('tag', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                result['actual']['tag'] = actual_tag.hex().upper()
                
                if actual_ciphertext == expected_ciphertext and actual_tag == expected_tag:
                    result['passed'] = True
                else:
                    if actual_ciphertext != expected_ciphertext:
                        result['error'] = f"密文不匹配"
                    else:
                        result['error'] = f"认证标签不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_xts(self, vector: Dict, result: Dict) -> Dict:
        """验证XTS模式"""
        try:
            # 1. 强制要求key2字段（XTS标准需两个独立密钥）
            if 'key_bytes' not in vector or 'key2_bytes' not in vector:
                result['error'] = "XTS模式必须提供key（主密钥）和key2（第二密钥）字段"
                return result
            key = vector['key_bytes']
            key2 = vector['key2_bytes']  # 必须用测试向量中的key2，不能用key替代

            # 2. 后续逻辑保持不变（用key2和tweak执行XTS加解密）
            tweak = vector['tweak_bytes']
            cipher = SM4(key)  # 主密钥用于加密
            # ... 原有加解密验证逻辑 ...
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_xts(plaintext, key2, tweak)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配"
                    return result
                
                # 验证解密
                actual_plaintext = cipher.decrypt_xts(expected_ciphertext, key2, tweak)
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_xts(self, vector: Dict, result: Dict) -> Dict:
        """验证XTS模式"""
        try:
            # 1. 强制要求key2字段（XTS标准需两个独立密钥）
            if 'key_bytes' not in vector or 'key2_bytes' not in vector:
                result['error'] = "XTS模式必须提供key（主密钥）和key2（第二密钥）字段"
                return result
            key = vector['key_bytes']
            key2 = vector['key2_bytes']  # 必须用测试向量中的key2，不能用key替代

            # 2. 后续逻辑保持不变（用key2和tweak执行XTS加解密）
            tweak = vector['tweak_bytes']
            cipher = SM4(key)  # 主密钥用于加密
            # ... 原有加解密验证逻辑 ...
            if 'plaintext_bytes' in vector and 'ciphertext_bytes' in vector:
                plaintext = vector['plaintext_bytes']
                expected_ciphertext = vector['ciphertext_bytes']
                
                actual_ciphertext = cipher.encrypt_xts(plaintext, key2, tweak)
                
                result['expected']['ciphertext'] = vector.get('ciphertext', '')
                result['actual']['ciphertext'] = actual_ciphertext.hex().upper()
                
                if actual_ciphertext == expected_ciphertext:
                    result['passed'] = True
                else:
                    result['error'] = f"密文不匹配"
                    return result
                
                # 验证解密
                actual_plaintext = cipher.decrypt_xts(expected_ciphertext, key2, tweak)
                
                if actual_plaintext == plaintext:
                    result['passed'] = True
                else:
                    result['error'] = f"解密后明文不匹配"
            else:
                result['error'] = "缺少明文或密文字段"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _validate_mac(self, vector: Dict, result: Dict) -> Dict:
        """验证MAC模式"""
        try:
            key = vector['key_bytes']
            cipher = SM4(key)
            
            if 'plaintext_bytes' not in vector:
                result['error'] = "缺少明文字段"
                return result
            
            plaintext = vector['plaintext_bytes']
            expected_mac = vector.get('tag_bytes', b'')
            
            if not expected_mac:
                result['error'] = "MAC模式需要tag字段"
                return result
            
            actual_mac = cipher.compute_mac(plaintext, len(expected_mac))
            
            result['expected']['mac'] = vector.get('tag', '')
            result['actual']['mac'] = actual_mac.hex().upper()
            
            if actual_mac == expected_mac:
                result['passed'] = True
            else:
                result['error'] = f"MAC不匹配"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def validate_file(self, file_path: str) -> Dict[str, Any]:
        """
        验证整个测试向量文件
        
        Args:
            file_path: 测试向量文件路径
        
        Returns:
            验证结果汇总
        """
        summary = {
            'file': os.path.basename(file_path),
            'total_vectors': 0,
            'passed': 0,
            'failed': 0,
            'error': 0,
            'passed_rate': 0.0,
            'results': []
        }
        
        try:
            # 解析向量
            vectors = parse_sm4_vector_file(file_path)
            
            if not vectors:
                summary['error'] = 1
                summary['results'].append({
                    'error': '无法解析文件'
                })
                return summary
            
            summary['total_vectors'] = len(vectors)
            
            # 验证每个向量
            for i, vector in enumerate(vectors):
                mode = vector.get('mode', 'UNKNOWN')
                
                result = self.validate_vector(vector, mode)
                result['index'] = i + 1
                summary['results'].append(result)
                
                if '_error' in vector:
                    summary['error'] += 1
                elif result['passed']:
                    summary['passed'] += 1
                elif result['passed'] is None:
                    summary['error'] += 1
                else:
                    summary['failed'] += 1
            
            # 计算通过率
            if summary['total_vectors'] > 0:
                valid_tests = summary['total_vectors'] - summary['error']
                if valid_tests > 0:
                    summary['passed_rate'] = summary['passed'] / valid_tests * 100
        
        except Exception as e:
            summary['error'] = summary['total_vectors']
            summary['error_message'] = str(e)
        
        return summary
    
    def validate_all_files(self, vector_dir: str) -> Dict[str, Any]:
        """
        验证目录下所有SM4测试向量文件
        
        Args:
            vector_dir: 测试向量目录
        
        Returns:
            所有文件的验证结果汇总
        """
        all_results = {
            'directory': vector_dir,
            'total_files': 0,
            'total_vectors': 0,
            'total_passed': 0,
            'total_failed': 0,
            'total_error': 0,
            'file_results': []
        }
        
        if not os.path.isdir(vector_dir):
            all_results['error'] = f"目录不存在: {vector_dir}"
            return all_results
        
        # 查找所有SM4测试向量文件
        sm4_files = sorted([
            f for f in os.listdir(vector_dir)
            if f.upper().startswith('SM4') and f.upper().endswith('.TXT')
        ])
        
        all_results['total_files'] = len(sm4_files)
        
        for filename in sm4_files:
            file_path = os.path.join(vector_dir, filename)
            
            self._log(f"\n验证: {filename}")
            result = self.validate_file(file_path)
            
            all_results['file_results'].append(result)
            all_results['total_vectors'] += result['total_vectors']
            all_results['total_passed'] += result['passed']
            all_results['total_failed'] += result['failed']
            all_results['total_error'] += result['error']
            
            self._log(f"  结果: {result['passed']}/{result['total_vectors']} 通过")
        
        # 计算总通过率
        valid_tests = all_results['total_vectors'] - all_results['total_error']
        if valid_tests > 0:
            all_results['overall_passed_rate'] = all_results['total_passed'] / valid_tests * 100
        
        return all_results


# 便利函数
def validate_sm4_vector_file(file_path: str, verbose: bool = True) -> Dict[str, Any]:
    """便利函数：验证单个SM4测试向量文件"""
    validator = SM4VectorValidator(verbose=verbose)
    return validator.validate_file(file_path)


def validate_all_sm4_vectors(vector_dir: str, verbose: bool = True) -> Dict[str, Any]:
    """便利函数：验证目录下所有SM4测试向量文件"""
    validator = SM4VectorValidator(verbose=verbose)
    return validator.validate_all_files(vector_dir)
