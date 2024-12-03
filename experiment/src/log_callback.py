import datetime

from keras.src.callbacks import Callback
import psutil


class LogCallback(Callback):

    def __init__(self):
        super().__init__()

    @staticmethod
    def get_memory_info():
        process = psutil.Process()
        memory_info = process.memory_info()
        return str(memory_info)

    def on_epoch_end(self, epoch, logs=None):
        print(str(datetime.datetime.now()), flush=True)
        print(f"{epoch + 1}:{self.get_memory_info()}", flush=True)
        print(logs, flush=True)
