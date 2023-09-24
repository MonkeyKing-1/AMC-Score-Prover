# %%
import unittest
import merkle_root
import sha3
import _pysha3
import _sha3
from Crypto.Hash import keccak
import numpy as np
import pandas as pd
import struct
import string
import json

# %%
class MerkleTests(unittest.TestCase):
    def test_mmt(self):
        arr = np.loadtxt('providers/merkle_root/test_files/input.txt', dtype=str)
        mmt = merkle_root.MaintainedMerkleTree(arr, "Andrew Gu", "Test", 2)
        # info_hash should equal hash(hash("Andrew Gu") + hash("Test"))
        info_hash = "e62e66d34042dd2818ce34bd70b12dbaca2b6829cb830e8b645aa0041b5ef52d"
        self.assertTrue(info_hash == mmt.info_hash)
    def test_mmt_proof(self):
        arr = np.loadtxt('providers/merkle_root/test_files/input.txt', dtype=str)
        mmt = merkle_root.MaintainedMerkleTree(arr, "Andrew Gu", "Test", 2)
        full_proof = mmt.give_proof(2)
        value = full_proof["value"]
        directions = full_proof["directions"]
        proof = full_proof["merkle_proof"]
        root = full_proof["root"]
        cum_root = value
        for i in range(len(proof) - 1, -1, -1):
            assert directions[i] < 2
            assert directions[i] >= 0
            if directions[i] == 0:
                cum_bytes = bytes.fromhex(cum_root)
                proof_bytes = bytes.fromhex(proof[i])
                keccak_hash = keccak.new(digest_bits=256)
                keccak_hash.update(cum_bytes)
                keccak_hash.update(proof_bytes)
                cum_root = keccak_hash.hexdigest()
            else:
                cum_bytes = bytes.fromhex(cum_root)
                proof_bytes = bytes.fromhex(proof[i])
                keccak_hash = keccak.new(digest_bits=256)
                keccak_hash.update(proof_bytes)
                keccak_hash.update(cum_bytes)
                cum_root = keccak_hash.hexdigest()
        self.assertTrue(cum_root == root)
    def test_mmt_conv(self):
        arr = np.loadtxt('providers/merkle_root/test_files/input.txt', dtype=str)
        mmt = merkle_root.MaintainedMerkleTree(arr, "Andrew Gu", "Test", 2)
        full_proof = mmt.give_proof(2)
        value = full_proof["value"]
        directions = full_proof["directions"]
        proof = full_proof["merkle_proof"]
        root = full_proof["root"]
        len_hex = "000000000000000000000000000000000000000000000000000000000000000e"
        nonce_hex = "0000000000000000000000000000000000000000000000000000000000000002"
        info_hash = "e62e66d34042dd2818ce34bd70b12dbaca2b6829cb830e8b645aa0041b5ef52d"
        self.assertTrue(len_hex == proof[2])
        self.assertTrue(nonce_hex == proof[1])
        self.assertTrue(info_hash == proof[0])
    def test_mimt_hash(self):
        immt = merkle_root.MaintainedInformativeMerkleTree('providers/merkle_root/test_files/example.csv', True, "Andrew Gu", "Test", 2)
        val_hash = immt.merkle_tree.data[4]
        vals = immt.raw_bytes[0]
        lens = immt.len_lists[0]
        self.assertTrue(val_hash == "bf26467a9db9c43a5d480ccd007f179c45f6c116a8f0838a132e6592a0be0268")
        self.assertTrue(vals == "andrewjeremiah")
        self.assertTrue(lens == [6, 8])
        self.assertTrue(immt.len_lists[1] == [3, 0])
    def test_mimt_pub_info(self):
        immt = merkle_root.MaintainedInformativeMerkleTree('providers/merkle_root/test_files/example.csv', True, "Andrew", "JEREMIAH", 5)
        response = immt.give_public_info()
        self.assertTrue(response["author"] == "Andrew")
        self.assertTrue(response["name"] == "JEREMIAH")
        self.assertTrue(response["header"] == ['hashes', 'dashes'])
        


# # %%
# infotree = merkle_root.MaintainedInformativeMerkleTree('test_files/example.csv', True, "Andrew", "JEREMIAH", 5)

# print(infotree.give_public_info())
# # %%

# %%
if __name__ == '__main__':
    unittest.main()