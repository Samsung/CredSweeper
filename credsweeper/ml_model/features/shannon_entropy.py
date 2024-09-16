from credsweeper.ml_model.features.reny_entropy import RenyiEntropy


class ShannonEntropy(RenyiEntropy):
    """Shannon entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 1.0, norm)
