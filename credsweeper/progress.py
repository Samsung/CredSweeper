from tqdm import tqdm


class Progress:
    """Class for tracking progress bar"""
    pbar = None

    @classmethod
    def on_progress(cls, unit: str, done: int, total: int):
        """Callback for progress bar"""

        if cls.pbar is None:
            cls.pbar = tqdm(total=total, unit=unit)
        if done >= total:
            cls.pbar.n = total
            cls.pbar.refresh()
            cls.pbar.close()
            cls.pbar = None
        else:
            cls.pbar.n = done
            cls.pbar.refresh()
