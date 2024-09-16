from credsweeper.ml_model.features.reny_entropy import RenyiEntropy


class HartleyEntropy(RenyiEntropy):
    """Hartley entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 0.0, norm)
