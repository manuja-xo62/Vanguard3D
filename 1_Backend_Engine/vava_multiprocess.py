import os
import sys
import json
import queue
import multiprocessing

model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'model'))
venv_packages = os.path.abspath(os.path.join(os.path.dirname(__file__), 'venv', 'Lib', 'site-packages'))
if venv_packages not in sys.path:
    sys.path.insert(0, venv_packages)
# ----------------------------------

import sounddevice as sd
from vosk import Model, KaldiRecognizer

# Thread-safe queue to pass audio chunks from the mic to the ML recognizer
audio_queue = queue.Queue()

def audio_callback(indata, frames, time, status):
    """Triggered by sounddevice for every audio block."""
    if status:
        print(status, file=sys.stderr)
    audio_queue.put(bytes(indata))

def get_working_input_device():
    """
    Attempts to find a working input device. Falls back to search if the default device is invalid.
    """
    try:
        # Check if the system's default input device is valid
        default_in = sd.default.device[0]
        if default_in != -1:
            sd.check_input_settings(device=default_in, samplerate=16000, channels=1, dtype='int16')
            return default_in
    except Exception:
        pass
        
    # Fallback: scan all devices to find the first valid input device
    for idx, dev in enumerate(sd.query_devices()):
        if dev['max_input_channels'] > 0:
            try:
                sd.check_input_settings(device=idx, samplerate=16000, channels=1, dtype='int16')
                return idx
            except Exception:
                continue
    return None

def run_stt_engine():
    
    ##Initializes the Vosk offline model and processes audio streams.
    ##Designed to run in an isolated process to prevent blocking the main server.
    
    model_path = "model"
    
    if not os.path.exists(model_path):
        print(f"[VAVA FATAL] Acoustic model not found at './{model_path}'.")
        print("Please download 'vosk-model-small-en-us' and extract it into a folder named 'model'.")
        return

    print("[VAVA] Loading offline acoustic model into memory...")
    try:
        model = Model(model_path)
        recognizer = KaldiRecognizer(model, 16000)
    except Exception as e:
        print(f"[VAVA FATAL] Failed to load model: {str(e)}")
        return
        
    # Resolve the working input device index dynamically
    device_idx = get_working_input_device()
    if device_idx is None:
        print("[VAVA FATAL] No working audio input device (microphone) found.")
        return
        
    print(f"[VAVA] Voice Assistant ONLINE (using device index {device_idx}). Listening for commands...")
    
    try:
        with sd.RawInputStream(samplerate=16000, blocksize=8000, device=device_idx,
                               dtype='int16', channels=1, callback=audio_callback):
            while True:
                data = audio_queue.get()
                if recognizer.AcceptWaveform(data):
                    result = json.loads(recognizer.Result())
                    text = result.get("text", "")
                    
                    if text:
                        print(f"\n[VAVA STT] Captured Command: '{text}'")
                        
                        if "scan" in text or "analyze" in text:
                            print("[VAVA ACTION] Triggering infrastructure threat scan...")
                        elif "patch" in text or "remediate" in text:
                            print("[VAVA ACTION] Activating zero-trust remediation protocol...")
    except KeyboardInterrupt:
        print("\n[VAVA] Voice Assistant shutting down gracefully.")
    except Exception as e:
        print(f"\n[VAVA ERROR] Audio stream interrupted: {str(e)}")

if __name__ == "__main__":
    stt_process = multiprocessing.Process(target=run_stt_engine, daemon=True)
    stt_process.start()
    
    try:
        stt_process.join()
    except KeyboardInterrupt:
        print("\n[*] Main process terminated.")
