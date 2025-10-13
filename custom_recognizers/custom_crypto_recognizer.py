from hashlib import sha256
from typing import List, Optional
from base_recognizer import BaseRecognizer, Pattern

# Constants for encoding types
BECH32 = 1
BECH32M = 2

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


class CustomCryptoRecognizer(BaseRecognizer):
    """Recognize common crypto account numbers using regex + checksum.
    """

    PATTERNS = [
        Pattern("Crypto (Medium)", r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}", 0.5),
    ]

    CONTEXT = ["wallet", "btc", "bitcoin", "crypto"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "CRYPTO",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate the Bitcoin address using checksum.

        :param pattern_text: The cryptocurrency address to validate.
        :return: True if the address is valid according to its respective
        format, False otherwise.
        """
        if pattern_text.startswith("1") or pattern_text.startswith("3"):
            # P2PKH or P2SH address validation
            try:
                bcbytes = self._decode_base58(str.encode(pattern_text))
                checksum = sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
                return bcbytes[-4:] == checksum
            except ValueError:
                return False
        elif pattern_text.startswith("bc1"):
            # Bech32 or Bech32m address validation
            if self.validate_bech32_address(pattern_text)[0]:
                return True
        return False

    @staticmethod
    def _decode_base58(bc: bytes) -> bytes:
        """Decode base58 encoded string."""
        digits58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        origlen = len(bc)
        bc = bc.lstrip(digits58[0:1])

        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        return n.to_bytes(origlen - len(bc) + (n.bit_length() + 7) // 8, "big")

    @staticmethod
    def bech32_polymod(values):
        """Compute the Bech32 checksum."""
        generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    @staticmethod
    def bech32_hrp_expand(hrp):
        """Expand the HRP into values for checksum computation."""
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @staticmethod
    def bech32_verify_checksum(hrp, data):
        """Verify a checksum given HRP and converted data characters."""
        const = CustomCryptoRecognizer.bech32_polymod(
            CustomCryptoRecognizer.bech32_hrp_expand(hrp) + data
        )
        if const == 1:
            return BECH32
        if const == BECH32M_CONST:
            return BECH32M
        return None

    @staticmethod
    def bech32_decode(bech):
        """Validate a Bech32/Bech32m string, and determine HRP and data."""
        if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
            bech.lower() != bech and bech.upper() != bech
        ):
            return (None, None, None)
        bech = bech.lower()
        pos = bech.rfind("1")
        if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
            return (None, None, None)
        if not all(x in CHARSET for x in bech[pos + 1 :]):
            return (None, None, None)
        hrp = bech[:pos]
        data = [CHARSET.find(x) for x in bech[pos + 1 :]]
        spec = CustomCryptoRecognizer.bech32_verify_checksum(hrp, data)
        if spec is None:
            return (None, None, None)
        return (hrp, data[:-6], spec)

    @staticmethod
    def validate_bech32_address(address):
        """Validate a Bech32 or Bech32m address."""
        hrp, data, spec = CustomCryptoRecognizer.bech32_decode(address)
        if hrp is not None and data is not None:
            return True, spec
        return False, None

    def get_supported_entities(self) -> List[str]:
        """Return list of supported entity types."""
        return [self.supported_entity]
