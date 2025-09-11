#!/usr/bin/env python3
"""
FunASR 功能测试脚本
测试语音识别功能是否正常工作
"""

import numpy as np
import sys
import time
import os

# 设置GPU环境变量
os.environ['USE_TORCH'] = '1'

def test_asr_basic():
    """测试基本ASR功能"""
    try:
        from funasr import AutoModel
        print("[TEST] FunASR import successful")

        # 创建一个简单的测试音频（正弦波）
        sample_rate = 16000
        duration = 2.0
        frequency = 440.0

        t = np.linspace(0, duration, int(sample_rate * duration), False)
        audio = np.sin(frequency * 2 * np.pi * t)

        # 转换为float32
        audio_float = audio.astype(np.float32)

        print("[TEST] Loading ASR model (GPU mode)...")
        model = AutoModel(
            model="paraformer-zh-streaming",
            model_revision="v2.0.4",
            device="cuda:0"
        )

        print("[TEST] Testing ASR...")
        result = model.generate(input=audio_float)

        print(f"[TEST] ASR result: {result}")
        print("[TEST] ASR test completed successfully!")

    except ImportError as e:
        print(f"[TEST] Import error: {e}")
        print("[TEST] Please install funasr: pip install funasr")
        return False
    except Exception as e:
        print(f"[TEST] Test failed: {e}")
        return False

    return True

def test_numpy_conversion():
    """测试numpy转换功能"""
    try:
        # 模拟PCM数据
        pcm_data = b'\x00\x01\x02\x03\x04\x05\x06\x07'

        # 转换为numpy数组
        audio_array = np.frombuffer(pcm_data, dtype=np.int16)
        print(f"[TEST] PCM to numpy conversion: {audio_array}")

        # 转换为float32
        audio_float = audio_array.astype(np.float32) / 32768.0
        print(f"[TEST] Numpy to float32 conversion: {audio_float}")

        print("[TEST] Numpy conversion test passed!")
        return True

    except Exception as e:
        print(f"[TEST] Numpy conversion failed: {e}")
        return False

if __name__ == "__main__":
    print("=== FunASR Integration Test ===")
    print()

    print("1. Testing numpy conversion...")
    numpy_ok = test_numpy_conversion()
    print()

    print("2. Testing FunASR...")
    asr_ok = test_asr_basic()
    print()

    if numpy_ok and asr_ok:
        print("✅ All tests passed! Ready to use ASR with zmq_test.py")
        print("Usage: python zmq_test.py --enable-asr")
    else:
        print("❌ Some tests failed. Please check dependencies.")
        sys.exit(1)
