import base64
import contextlib
import logging
import random
from abc import ABC
from typing import List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class PkcsScanner(AbstractScanner, ABC):
    """Implements pkcs12 scanning"""

    @staticmethod
    def load(data: bytes, password: Optional[bytes]) -> Optional[PrivateKeyTypes]:
        """Try to load private key from PKCS1, PKCS8 and PKCS12 formats"""
        with contextlib.suppress(Exception):
            # PKCS1, PKCS8 probes
            private_key = load_der_private_key(data, password)
            return private_key
        with contextlib.suppress(Exception):
            # PKCS12 probe
            private_key, _certificate, _additional_certificates = load_key_and_certificates(data, password)
            return private_key
        return None

    @staticmethod
    def check(pkey: PrivateKeyTypes) -> bool:
        """Check private key with encrypt-decrypt random data"""
        if isinstance(pkey, (EllipticCurvePrivateKey, DSAPrivateKey, Ed448PrivateKey, Ed25519PrivateKey, DHPrivateKey,
                             X448PrivateKey, X25519PrivateKey)):
            # One does not simply perform check the keys
            return True
        if isinstance(pkey, (EllipticCurvePublicKey, DSAPublicKey, Ed448PublicKey, Ed25519PublicKey, DHPublicKey,
                             X448PublicKey, X25519PublicKey)):
            # These aren't the keys we're looking for
            return False
        # DSA, RSA
        data = random.randbytes(42)
        pd = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.MD5()), algorithm=hashes.MD5(), label=None)
        ciphertext = pkey.public_key().encrypt(data, padding=pd)
        refurb = pkey.decrypt(ciphertext, padding=pd)
        return bool(refurb == data)

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan PKCS12 to open with standard password"""
        for pw_probe in self.config.bruteforce_list:
            try:
                password = pw_probe.encode() if pw_probe else None
                if pkey := PkcsScanner.load(data_provider.data, password):
                    if not PkcsScanner.check(pkey):
                        logger.debug("False alarm %s", data_provider.info)
                        return []
                    candidate = Candidate.get_dummy_candidate(
                        self.config,  #
                        data_provider.file_path,  #
                        data_provider.file_type,  #
                        f"{data_provider.info}|PKCS:{repr(password)} is the password",  #
                        "PKCS")
                    candidate.line_data_list[0].line = base64.b64encode(data_provider.data).decode()
                    candidate.line_data_list[0].value = repr(password)
                    return [candidate]
            except Exception as pkcs_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe}:{pkcs_exc}")
        return None
