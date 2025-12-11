import itertools
import math
import pathlib

import matplotlib.pyplot as plt
from keras.src.callbacks import History
from matplotlib import image as mpimg

METRICS = ["loss", "binary_accuracy", "precision", "recall"]
NCOLS = 2  # GRAPHS_PER_ROW
NROWS = math.ceil(len(METRICS) / NCOLS)


def save_plot(stamp: str, title: str, history: History, dir_path: pathlib.Path, best_epoch: int, info: str):
    plt.clf()
    fig, axes = plt.subplots(nrows=NROWS, ncols=NCOLS, figsize=(16, 9), tight_layout=True)

    fig.suptitle(f"{stamp} {title}")

    # train displays "Epoch 1/7", so let the plot starts from 1
    x = [x + 1 for x in history.epoch]

    for idx, characteristic in itertools.zip_longest(range(NROWS * NROWS), METRICS):
        axes_x = idx % NCOLS
        axes_y = idx // NCOLS
        if characteristic:
            y_train = history.history[characteristic]
            y_test = history.history[f"val_{characteristic}"]
            axes[axes_x, axes_y].plot(x, y_train, label="train")
            axes[axes_x, axes_y].plot(x, y_test, label="test")
            axes[axes_x, axes_y].set_title(characteristic)
            axes[axes_x, axes_y].legend(loc="upper left")
            axes[axes_x, axes_y].grid(visible=True, which="both", color="grey", linewidth=0.75, linestyle="dotted")
            axes[axes_x, axes_y].set_xticks(range(min(x), max(x) + 1, 1), minor=True)
            axes[axes_x, axes_y].axvline(x=best_epoch, color='green', linestyle='--', linewidth=1)
        else:
            axes[axes_x, axes_y].axis('off')

    fig.text(0.001, 0.001, info, fontsize=10, color='green', backgroundcolor='white')
    plt.savefig(dir_path / f"{stamp}.png", dpi=96)
    plt.close('all')


def stamp_plot(stamp: str, dir_path: pathlib.Path, info: str):
    file_path = dir_path / f"{stamp}.png"
    image = mpimg.imread(file_path)
    plt.figure(figsize=(16, 9), tight_layout=True)
    plt.imshow(image)
    plt.text(222, 333, info, fontsize=10, color='red', backgroundcolor='white')
    plt.axis('off')
    plt.savefig(file_path, bbox_inches='tight', pad_inches=0, dpi=96)
    plt.close('all')
