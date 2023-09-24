# %%
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
max_field_num = 16
max_bytes = 1024
# %%
class DataPacket:
    def __init__(self, concat, lens):
        self.concat = concat
        self.lens = lens
    def dictify(self):
        return dict({"concat": self.concat, "lens": self.lens})

class Word:
    def __init__(self, word):
        self.bytes = word
    def dictify(self):
        return dict({"bytes": self.bytes})

def hex_to_bytes(hexes):
    bytestrings = np.empty(len(hexes), dtype= bytearray)
    for i in range(len(hexes)):
        bytestrings[i] = bytearray.fromhex(hexes[i])
    return bytestrings

def string_to_hi_lo(s):
    assert len(s) <= 64
    for i in range(64 - len(s)):
        s += chr(0)
    return s[:32], s[32:]

def int_to_hex64(n):
    digs = ""
    for _ in range(64):
        digit = n % 16
        if digit >= 10:
            digs = chr(87 + digit) + digs
        else:
            digs = str(digit) + digs
        n = n // 16
    return digs

def int_to_hex4(n):
    digs = ""
    for _ in range(4):
        digit = n % 16
        if digit >= 10:
            digs = chr(87 + digit) + digs
        else:
            digs = str(digit) + digs
        n = n // 16
    return digs

def next_pow2(n):
    i = 1
    depth = 0
    while i < n:
        i *= 2
        depth += 1
    return i, depth
    


# array of hexstrings to tree of hexes
def merkleize_safe_hexes(hashes):
    for hash in hashes:
        assert len(hash) == 64
    assert num_hashes > 0
    zeros = "0000000000000000000000000000000000000000000000000000000000000000"
    tot, depth = next_pow2(num_hashes)
    blanks = np.full(tot - num_hashes, zeros)
    hashes = np.append(hashes, blanks)
    tree = np.full(tot, zeros)
    tree = np.append(tree, hashes)
    for i in range(tot - 1, 0, -1):
        keccak_hash = keccak.new(digest_bits=256)
        bytes1 = bytes.fromhex(tree[2 * i])
        bytes2 = bytes.fromhex(tree[2 * i + 1])
        keccak_hash.update(bytes1)
        keccak_hash.update(bytes2)
        tree[i] = keccak_hash.hexdigest()
    return tree

# %%

def concatrow(row):
    keys = row.keys()
    len_list = []
    tot_word = ""
    assert len(keys) <= max_field_num
    for key in keys:
        # print(key, " ", row[key])
        len_list.append(len(row[key]))
        tot_word += row[key]
    assert len(tot_word) <= max_bytes
    return tot_word, len_list

def hash_data_packet(fields, field_lens):
    field_bytes = bytes(fields, 'utf-8')
    assert len(field_bytes) <= max_bytes
    assert len(field_lens) <= max_field_num
    len_cum_string = ""
    for length in field_lens:
        len_cum_string += int_to_hex4(length)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(field_bytes)
    data_hash = bytes.fromhex(keccak_hash.hexdigest())
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(bytes.fromhex(len_cum_string))
    lens_hash = bytes.fromhex(keccak_hash.hexdigest())
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(data_hash)
    keccak_hash.update(lens_hash)
    return keccak_hash.hexdigest()


def hashrow(row):
    return hash_data_packet(row[0], row[1])

class MaintainedInformativeMerkleTree:
    def __init__(self, file_name, fields_are_named, maker, name, nonce):
        if fields_are_named:
            df = pd.read_csv(filepath_or_buffer=file_name, header=0, dtype=str)
            self.header = df.keys().to_numpy()
            lens = np.vectorize(len)
            self.header_lens = lens(self.header)
        else:
            df = pd.read_csv(filepath_or_buffer=file_name, header=None, dtype=str)
            num_keys = len(df.keys())
            self.header = np.full(num_keys, '', dtype=str)
            lens = np.vectorize(len)
            self.header_lens = lens(self.header)
        header_concat = ''
        for field in self.header:
            header_concat += field
        self.header_concat = header_concat
        self.header_root = hash_data_packet(header_concat, self.header_lens)
        df.fillna(value='', inplace=True)
        df_len = len(df)
        df = df.apply(func=concatrow, axis=1, result_type='expand')
        df_hashes = df.apply(func=hashrow, axis=1)
        self.merkle_tree = MaintainedMerkleTree(df_hashes.to_numpy(), maker, name, nonce)
        self.len_lists = df[1].to_numpy()
        self.raw_bytes = df[0].to_numpy()
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(bytes.fromhex(self.merkle_tree.root))
        keccak_hash.update(bytes.fromhex(self.header_root))
        self.root = keccak_hash.hexdigest()
    def give_public_info(self):
        answer_dict = self.merkle_tree.give_public_info()
        answer_dict["header"] = self.header.tolist()
        return answer_dict
    def give_proof(self, idx):
        ans = self.merkle_tree.give_proof(idx)
        ans["merkle_proof"] = np.append([self.header_root], ans["merkle_proof"]).tolist()
        ans["root"] = self.root 
        ans["directions"] = np.append([0], ans["directions"]).tolist()
        ans["name"] = Word(self.merkle_tree.name).dictify()
        ans["author"] = Word(self.merkle_tree.maker).dictify()
        ans["header"] = DataPacket(self.header_concat, self.header_lens.tolist()).dictify()
        ans["fields"] = DataPacket(self.raw_bytes[idx], self.len_lists[idx]).dictify()
        return ans
class CompressedInformativeMerkleTree:
    def __init__(self, mimt_tree):
        self.name = mimt.name
        self.maker = mtn_tree.maker
        self.header = self.header
        self.root = mtn.root
    def give_public_info(self):
        answer_dict = dict({"root": self.root, "author": self.maker, "name": self.name, "header": self.header.tolist()})
        return answer_dict

class MaintainedMerkleTree:
    def __init__(self, hashes, maker, name, nonce):
        for hash in hashes:
            assert len(hash) == 64
        num_hashes = len(hashes)
        assert num_hashes > 0
        self.maker = maker
        self.name = name
        self.nonce = nonce
        assert type(nonce) is int
        zeros = "0000000000000000000000000000000000000000000000000000000000000000"
        tot, depth = next_pow2(num_hashes)
        blanks = np.full(tot - num_hashes, zeros)
        hashes = np.append(hashes, blanks)
        tree = np.full(tot, zeros)
        tree = np.append(tree, hashes)
        for i in range(tot - 1, 0, -1):
            keccak_hash = keccak.new(digest_bits=256)
            bytes1 = bytes.fromhex(tree[2 * i])
            bytes2 = bytes.fromhex(tree[2 * i + 1])
            keccak_hash.update(bytes1)
            keccak_hash.update(bytes2)
            tree[i] = keccak_hash.hexdigest()
        self.data = tree
        self.len = num_hashes
        self.len_bytes = int_to_hex64(self.len)
        self.depth = depth
        data_bytes = bytes.fromhex(self.data[1])
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(data_bytes)
        len_bytes = bytes.fromhex(int_to_hex64(self.len))
        keccak_hash.update(len_bytes)
        self.db_root = keccak_hash.hexdigest()
        
        # hash the name of the maker
        keccak_hash = keccak.new(digest_bits=256)
        maker_bytes = bytes(maker, 'utf-8')
        keccak_hash.update(maker_bytes)
        maker_hash = keccak_hash.hexdigest()
        #hash the name of the db
        keccak_hash = keccak.new(digest_bits=256)
        name_bytes = bytes(name, 'utf-8')
        keccak_hash.update(name_bytes)
        name_hash = keccak_hash.hexdigest()
        keccak_hash = keccak.new(digest_bits=256)
        name_hash_bytes = bytes.fromhex(name_hash)
        maker_hash_bytes = bytes.fromhex(maker_hash)
        keccak_hash = keccak_hash.update(maker_hash_bytes)
        keccak_hash = keccak_hash.update(name_hash_bytes)
        self.info_hash = keccak_hash.hexdigest()
        db_hash_bytes = bytes.fromhex(self.db_root)
        nonce_bytes = bytes.fromhex(int_to_hex64(nonce))
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash = keccak_hash.update(db_hash_bytes)
        keccak_hash = keccak_hash.update(nonce_bytes)
        temp_hash = keccak_hash.hexdigest()
        temp_bytes = bytes.fromhex(temp_hash)
        info_hash_bytes = bytes.fromhex(self.info_hash)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash = keccak_hash.update(temp_bytes)
        keccak_hash = keccak_hash.update(info_hash_bytes)
        self.root = keccak_hash.hexdigest()
    
    def give_proof(self, idx):
        depth = self.depth
        length = self.len
        root = self.root
        assert idx < self.len
        assert idx >= 0
        directions = np.empty(self.depth + 3, dtype=int)
        merkle_proof = np.array([])
        n = idx
        directions[0] = 0
        directions[1] = 0
        directions[2] = 0
        for i in range(depth + 2, 2, -1):
            directions[i] = n % 2
            n = n // 2
        merkle_proof = np.append(merkle_proof, self.info_hash)
        nonce_bytes = int_to_hex64(self.nonce)
        merkle_proof = np.append(merkle_proof, nonce_bytes)
        merkle_proof = np.append(merkle_proof, self.len_bytes)
        index = 1
        for i in range(0, depth):
            index = 2 * index + directions[i + 3]
            merkle_proof = np.append(merkle_proof, self.data[index ^ 1])
        value = self.data[index]
        proof_dict = dict({"root": root, "directions": directions.tolist(), "merkle_proof": merkle_proof.tolist()})
        #return root, length, depth, value, directions, merkle_proof
        return proof_dict
    def give_public_info(self):
        answer_dict = dict({"root": self.root, "author": self.maker, "name": self.name})
        return answer_dict
        
# %%
class CompressedMerkleTree:
    def __init__(self, mtn_tree):
        self.name = mtn_tree.name
        self.maker = mtn_tree.maker
        # self.db_root = mtn_tree.db_root
        # self.nonce = mtn.nonce
        self.root = mtn.root
    
    def give_public_info(self):
        answer_dict = dict({"root": self.root, "author": self.maker, "name": self.name})
        return answer_dict
# %%

# arr = np.loadtxt("input.txt",
#                  delimiter=",", dtype=str)
# newtree = MaintainedMerkleTree(arr, "ANDREW", "BOB", 4)


# print(infotree.header)

# new_proof_dict = newtree.give_proof(3)
 
# # Serializing json
# json_object = json.dumps(new_proof_dict, indent=4)

# # Writing to sample.json
# with open("new_sample.json", "w") as outfile:
#     outfile.write(json_object)

# # %%
# immt = MaintainedInformativeMerkleTree('test_files/example.csv', True, "Andrew Gu", "Test", 2)

# new_proof_dict = immt.give_proof(2)
 
# # Serializing json
# json_object = json.dumps(new_proof_dict, indent=4)

# # Writing to sample.json
# with open("new_sample.json", "w") as outfile:
#     outfile.write(json_object)