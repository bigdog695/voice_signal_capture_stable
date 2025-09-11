#!/usr/bin/env python3
"""
检查GPU环境配置
确保FunASR能在GPU模式下正常运行
"""

import os
import sys

def check_environment():
    """检查环境配置"""
    print("=== GPU环境检查 ===")

    # 检查环境变量
    cuda_visible = os.environ.get('CUDA_VISIBLE_DEVICES', 'Not set')
    use_torch = os.environ.get('USE_TORCH', 'Not set')

    print(f"CUDA_VISIBLE_DEVICES: {cuda_visible}")
    print(f"USE_TORCH: {use_torch}")

    # 检查CUDA可用性
    try:
        import torch
        cuda_available = torch.cuda.is_available()
        print(f"PyTorch CUDA available: {cuda_available}")

        if cuda_available:
            print("✅ CUDA is available, GPU mode will be used")

            # 获取GPU信息
            device_count = torch.cuda.device_count()
            print(f"CUDA device count: {device_count}")

            for i in range(device_count):
                gpu_name = torch.cuda.get_device_name(i)
                gpu_memory = torch.cuda.get_device_properties(i).total_memory / 1024**3
                print(f"GPU {i}: {gpu_name} ({gpu_memory:.1f} GB)")
        else:
            print("❌ CUDA not available, please check CUDA installation")
            return False

    except ImportError:
        print("❌ PyTorch not installed")
        return False
    except Exception as e:
        print(f"❌ PyTorch check failed: {e}")
        return False

    # 检查numpy
    try:
        import numpy as np
        print("✅ NumPy available")
    except ImportError:
        print("❌ NumPy not installed")
        return False

    # 检查funasr
    try:
        import funasr
        print("✅ FunASR available")
        print(f"FunASR version: {funasr.__version__ if hasattr(funasr, '__version__') else 'Unknown'}")
    except ImportError:
        print("❌ FunASR not installed")
        return False

    return True

def test_gpu_inference():
    """测试GPU推理"""
    print("\n=== GPU推理测试 ===")

    try:
        # 设置GPU模式
        os.environ['USE_TORCH'] = '1'

        from funasr import AutoModel
        import numpy as np

        print("正在加载模型（GPU模式）...")
        model = AutoModel(
            model="paraformer-zh-streaming",
            model_revision="v2.0.4",
            device="cuda:0"
        )

        print("✅ 模型加载成功")

        # 创建测试音频
        sample_rate = 16000
        duration = 1.0
        t = np.linspace(0, duration, int(sample_rate * duration), False)
        audio = np.sin(440 * 2 * np.pi * t).astype(np.float32)

        print("正在进行推理测试...")
        result = model.generate(input=audio)

        print("✅ 推理测试成功")
        print(f"测试结果: {result}")

        return True

    except Exception as e:
        print(f"❌ GPU推理测试失败: {e}")
        return False

if __name__ == "__main__":
    print("FunASR GPU模式环境检查\n")

    env_ok = check_environment()
    if not env_ok:
        print("\n❌ 环境检查失败，请先安装必要的依赖")
        sys.exit(1)

    inference_ok = test_gpu_inference()

    if env_ok and inference_ok:
        print("\n✅ 所有检查通过！可以开始使用FunASR GPU模式")
        print("使用方法: python zmq_test.py --enable-asr")
    else:
        print("\n❌ 检查失败，请检查配置和依赖")
        sys.exit(1)
