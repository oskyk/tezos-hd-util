from base58 import b58encode_check
from pyblake2 import blake2b
import btcpy
from btcpy.structs.hd import ExtendedPrivateKey, ExtendedPublicKey


class XPrv(object):
    def __init__(self, key):
        btcpy.setup.setup('mainnet')
        self.key = ExtendedPrivateKey.decode(key)

    def derive(self, path):
        return XPrv(self.key.derive(path).encode())

    def prv(self):
        spsk = b'\x11\xa2\xe0\xc9'
        return b58encode_check(spsk + self.key.key.serialize())

    def pub(self):
        sppk = b'\x03\xfe\xe2V'
        return b58encode_check(sppk + self.key.key.pub().serialize())

    def pkh(self):
        tz2 = b'\x06\xa1\xa1'
        pkh = blake2b(data=self.key.key.pub().serialize(), digest_size=20).digest()
        return b58encode_check(tz2 + pkh)


class XPub(object):
    def __init__(self, key):
        btcpy.setup.setup('mainnet')
        self.key = ExtendedPublicKey.decode(key)

    def derive(self, path):
        return XPub(self.key.derive(path).encode())

    def prv(self):
        sppk = b'\x03\xfe\xe2V'
        return b58encode_check(sppk + self.key.key.serialize())

    def pkh(self):
        tz2 = b'\x06\xa1\xa1'
        pkh = blake2b(data=self.key.key.serialize(), digest_size=20).digest()
        return b58encode_check(tz2 + pkh)
