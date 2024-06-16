import pathlib
import pickle

import matplotlib.pyplot as plt
from keras.src.callbacks import History


def save_plot(stamp: str, title: str, history: History, dir_path: pathlib.Path):
    with open(dir_path / f"history-{stamp}.pickle", "wb") as f:
        pickle.dump(history, f)
    plt.clf()
    fig, axes = plt.subplots(nrows=2, ncols=2, figsize=(16, 9), tight_layout=True)

    fig.suptitle(f"{stamp} {title}")

    # train displays "Epoch 1/7", so let the plot starts from 1
    x = [x + 1 for x in history.epoch]

    for idx, characteristic in enumerate(["loss", "binary_accuracy", "precision", "recall"]):
        axes_x = (1 & idx)
        axes_y = (2 & idx) >> 1
        y_train = history.history[characteristic]
        y_test = history.history[f"val_{characteristic}"]
        axes[axes_x, axes_y].plot(x, y_train, label="train")
        axes[axes_x, axes_y].plot(x, y_test, label="test")
        axes[axes_x, axes_y].set_title(characteristic)
        axes[axes_x, axes_y].legend(loc="upper left")
        axes[axes_x, axes_y].grid(visible=True, which="both", color="grey", linewidth=0.75, linestyle="dotted")
        axes[axes_x, axes_y].set_xticks(range(min(x), max(x) + 1, 1), minor=True)

    plt.savefig(dir_path / f"{stamp}.png", dpi=96)


# dbg
if __name__ == "__main__":
    _dir_path = pathlib.Path("results")
    current_time = "20240615_225056"
    with open(f"results/history-{current_time}.pickle", "rb") as _f:
        fit_history = pickle.load(_f)
    save_plot(current_time, "title", fit_history, _dir_path)
