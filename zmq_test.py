#!/usr/bin/env python3

import argparse
import json
import os
import signal
import sys
import time
import wave
import numpy as np
ip_white_list = ["192.168.10.19"]

def write_wav(path, pcm_bytes, sample_rate=8000, channels=1, sample_width_bytes=2):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with wave.open(path, 'wb') as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sample_width_bytes)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm_bytes)


def main():
    parser = argparse.ArgumentParser(description='ZMQ test consumer for RTP PCM chunks with ASR')
    parser.add_argument('--endpoint', default='tcp://0.0.0.0:5555', help='ZMQ endpoint to bind/connect (default: tcp://0.0.0.0:5555)')
    parser.add_argument('--mode', choices=['bind', 'connect'], default='bind', help='Bind or connect (default: bind)')
    parser.add_argument('--save-wav', action='store_true', help='Save a WAV file per finished call and direction')
    parser.add_argument('--out-dir', default='zmq_received', help='Directory to save WAVs when --save-wav is set')
    parser.add_argument('--linger-ms', type=int, default=0, help='ZMQ socket LINGER in ms (default: 0)')
    parser.add_argument('--print-every', type=int, default=20, help='Print a line every N chunks per session (default: 20)')
    parser.add_argument('--enable-asr', action='store_true', help='Enable real-time speech recognition')
    parser.add_argument('--asr-model', default='paraformer-zh-streaming', help='ASR model name (default: paraformer-zh-streaming)')
    args = parser.parse_args()

    # 初始化ASR模型（GPU模式）
    asr_model = None
    if args.enable_asr:
        try:
            # 设置GPU环境变量
            os.environ['USE_TORCH'] = '1'

            from funasr import AutoModel
            print("[ASR] Loading model (GPU mode)...")

            asr_model = AutoModel(
                model=args.asr_model,
                model_revision="v2.0.4",
                vad_model="fsmn-vad",
                vad_model_revision="v2.0.4",
                punc_model="ct-punc",
                punc_model_revision="v2.0.4",
                device="cuda:0",  # 使用GPU
            )
            print(f"[ASR] Model {args.asr_model} loaded successfully (GPU mode)")
        except ImportError as e:
            print(f"[ASR] Failed to import funasr: {e}")
            print("[ASR] Please install funasr: pip install funasr")
            sys.exit(1)
        except Exception as e:
            print(f"[ASR] Failed to load model: {e}")
            print("[ASR] Note: Make sure CUDA is properly installed")
            sys.exit(1)

    try:
        import zmq
    except Exception as e:
        print(f"Failed to import zmq: {e}", file=sys.stderr)
        sys.exit(1)

    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.PULL)
    sock.setsockopt(zmq.LINGER, args.linger_ms)

    if args.mode == 'bind':
        sock.bind(args.endpoint)
        print(f"[ZMQ] PULL bind on {args.endpoint}")
    else:
        sock.connect(args.endpoint)
        print(f"[ZMQ] PULL connect to {args.endpoint}")

    # session state: {(peer_ip, source, call_id): {buffer: bytearray, chunks: int, bytes: int, first_ts: float, last_ts: float}}
    sessions = {}
    # per peer+source current call id
    call_ids = {}  # {(peer_ip, source): int}

    running = True

    def handle_sigint(signum, frame):
        nonlocal running
        running = False
        print("\n[ZMQ] Stopping...")

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    def get_session(peer_ip, source, start_ts=None):
        key_ps = (peer_ip, source)
        call_id = call_ids.get(key_ps, 1)
        key = (peer_ip, source, call_id)
        if key not in sessions:
            sessions[key] = {
                'buffer': bytearray(),
                'chunks': 0,
                'bytes': 0,
                'first_ts': start_ts,
                'last_ts': start_ts
            }
        return key, sessions[key]

    def rotate_call(peer_ip, source):
        key_ps = (peer_ip, source)
        call_ids[key_ps] = call_ids.get(key_ps, 1) + 1

    def process_asr(peer_ip, source, pcm_bytes, meta, asr_model):
        """处理语音识别"""
        if not asr_model or not pcm_bytes:
            return

        try:
            # PCM -> numpy -> 升采样 -> 归一化
            audio_array = np.frombuffer(pcm_bytes, dtype=np.int16)
            import scipy.signal
            audio_16k = scipy.signal.resample_poly(audio_array, up=2, down=1)
            audio_16k = audio_16k.astype(np.float32) / 32768.0

            # 语音识别
            result = asr_model.generate(input=audio_16k)
            if result and len(result) > 0 and result[0].get('text') is not None:
                text = result[0]['text'].strip()
                if text:
                    print(f"meta={meta}\ntext={text}")
        except Exception as e:
            print(f"[ASR ERROR] {peer_ip} {source}: {e}")

    def save_and_clear(key, sess):
        peer_ip, source, call_id = key
        dur_sec = (len(sess['buffer']) / 2) / 8000.0
        print(f"[CALL DONE] {peer_ip} {source} call#{call_id}: chunks={sess['chunks']} bytes={sess['bytes']} duration≈{dur_sec:.2f}s ts=[{sess['first_ts']}, {sess['last_ts']}]")
        if args.save_wav and sess['buffer']:
            ip_clean = peer_ip.replace('.', '_')
            out_path = os.path.join(args.out_dir, f"{ip_clean}_{source}_call{call_id}.wav")
            try:
                write_wav(out_path, bytes(sess['buffer']))
                print(f"  saved: {out_path}")
            except Exception as e:
                print(f"  save failed: {e}")
        # clear
        del sessions[key]
        rotate_call(peer_ip, source)

    last_chunk_times = {}
    while running:
        try:
            meta_raw, pcm = sock.recv_multipart(flags=zmq.NOBLOCK)
        except zmq.Again:
            time.sleep(0.01)
            continue
        except Exception as e:
            print(f"[ZMQ] recv error: {e}")
            continue

        try:
            meta = json.loads(meta_raw.decode('utf-8'))
        except Exception as e:
            print(f"[ZMQ] bad meta json: {e}")
            continue

        peer_ip = meta.get('peer_ip', 'unknown')
        if peer_ip not in ip_white_list:
            continue
        source = meta.get('source', 'unknown')
        start_ts = meta.get('start_ts')
        end_ts = meta.get('end_ts')
        is_finished = bool(meta.get('IsFinished', False))

        # 分析chunk时间重叠
        key = (peer_ip, source)
        last = last_chunk_times.get(key)
        if last is not None:
            last_end = last['end_ts']
            interval = start_ts - last_end if (start_ts is not None and last_end is not None) else None
            print(f"[CHUNK TIME] {key}: last_end={last_end}, this_start={start_ts}, interval={interval}, this_end={end_ts}")
            if end_ts is not None and last_end is not None and end_ts < last_end:
                print(f"[WARNING] chunk end_ts回退: {end_ts} < {last_end}")
            if start_ts is not None and last_end is not None and start_ts < last_end:
                print(f"[WARNING] chunk有重叠: start_ts={start_ts} < last_end={last_end}")
        last_chunk_times[key] = {'start_ts': start_ts, 'end_ts': end_ts}

        key, sess = get_session(peer_ip, source, start_ts)

        if pcm:
            print(f"[DEBUG] 收到PCM: len={len(pcm)}, type={type(pcm)}")
            sess['buffer'].extend(pcm)
            sess['bytes'] += len(pcm)
            sess['chunks'] += 1
            if sess['first_ts'] is None:
                sess['first_ts'] = start_ts
            sess['last_ts'] = end_ts if end_ts is not None else sess['last_ts']

            # 实时语音识别
            if asr_model:
                print(f"[DEBUG] 调用process_asr, peer_ip={peer_ip}, source={source}, chunk_size={len(pcm)}")
                process_asr(peer_ip, source, pcm, meta, asr_model)

        if sess['chunks'] % max(1, args.print_every) == 0:
            print(f"[CHUNK] {peer_ip} {source} call#{key[2]} chunks={sess['chunks']} bytes={sess['bytes']}")

        if is_finished:
            # If no bytes and just a finish marker, still close session nicely
            save_and_clear(key, sess)
            sys.exit(0)

    # graceful shutdown: close any active sessions
    if sessions:
        print(f"[ZMQ] Flushing {len(sessions)} active sessions...")
        for key, sess in list(sessions.items()):
            save_and_clear(key, sess)

    try:
        sock.close()
    finally:
        ctx.term()


if __name__ == '__main__':
    main()


