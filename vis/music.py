import numpy as np
import sounddevice as sd
from ..trace.logger import AetherLog

def play_tone(frequency=440, duration=1.0, samplerate=44100):
    t = np.linspace(0, duration, int(samplerate * duration), endpoint=False)
    wave = 0.5 * np.sin(2 * np.pi * frequency * t)
    sd.play(wave, samplerate)
    sd.wait()

def normalize(arr):
    arr = np.asarray(arr)
    return (arr - arr.min()) / (arr.max() - arr.min())

def log_to_tones(log: AetherLog, min_freq=440, max_freq=880):
    return normalize([frame.instruction_address for frame in log.frames]) * (max_freq - min_freq) + min_freq

if __name__ == "__main__":
    # # Load fib.al as an Aether log
    # with open("fib.al", "r") as f:
    #     fib_log = AetherLog.from_json(f.read())
    #
    # frequencies = log_to_tones(fib_log)
    #
    # for frequency in frequencies:
    print(normalize([1, 3, 4]))
    print(play_tone(1000, 1))
    print(print("hello world"))
