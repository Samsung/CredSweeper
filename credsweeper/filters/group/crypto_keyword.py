from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import ValueSealedSecretCheck, ValueEntropyCheck, ValueDictionaryKeywordCheck
from credsweeper.filters.group.group import Group


class CryptoKeyword(Group):
    """Crypto Keyword filter group for cryptographic primitives (key, salt, nonce, etc.)"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.KEYWORD)
        self.filters.extend([ValueDictionaryKeywordCheck(), ValueSealedSecretCheck(), ValueEntropyCheck(threshold=64)])
