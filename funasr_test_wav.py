import sys
from funasr import AutoModel
import soundfile as sf

if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <wav_file>")
    sys.exit(1)

wav_path = sys.argv[1]

# 选择模型名，可根据需要修改
MODEL_NAME = "paraformer-zh-streaming"

# 加载模型（自动选择CPU/GPU）
asr_model = AutoModel(model=MODEL_NAME, device="cpu")

# 读取wav文件
wav, sr = sf.read(wav_path)
if wav.ndim > 1:
    wav = wav[:, 0]  # 只取第一通道

# 如果采样率不是16k，建议先升采样到16k
if sr != 16000:
    import scipy.signal
    wav = scipy.signal.resample_poly(wav, 16000, sr)
    sr = 16000

# 推理
result = asr_model.generate(input=wav)
print("ASR结果:", result)
if result and len(result) > 0 and result[0].get('text'):
    print("识别文本:", result[0]['text'].strip())
else:
    print("未识别出文本")
