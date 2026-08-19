from tqdm import tqdm


class Progress:
    """Class for tracking progress bar"""

    def __init__(self):
        self.progress_bar = None

    def callback(self, unit: str, done: int, total: int):
        """Callback for progress bar"""
        if self.progress_bar is None:
            self.progress_bar = tqdm(total=total, unit=unit)
        elif self.progress_bar.unit != unit:
            self.progress_bar.close()
            self.progress_bar = tqdm(total=total, unit=unit)
        if done >= total:
            self.progress_bar.n = total
            self.progress_bar.refresh()
            self.progress_bar.close()
            self.progress_bar = None
        else:
            self.progress_bar.n = done
            self.progress_bar.refresh()
