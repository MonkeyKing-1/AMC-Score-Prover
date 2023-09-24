# %%
from merkle_root import merkle_root
import sha3
import _pysha3
import _sha3
from Crypto.Hash import keccak
import numpy as np
import pandas as pd
import struct
import string
import json
import sys


if __name__ == "__main__":
    if len(sys.argv) < 6:
        assert False
    year = sys.argv[1]
    test = sys.argv[2]
    outputname = sys.argv[3]
    newtree = merkle_root.MaintainedInformativeMerkleTree("providers/data/" + year + " AMC" + test + " Dist Honor Roll.csv", True, "Andrew Gu", year + " AMC 12A Distinguished Honor Roll", 0)
    ind = sys.argv[4]
    new_proof_dict = newtree.give_proof(int(ind))
    new_proof_dict["max_depth"] = 20
    # Serializing json
    json_object = json.dumps(new_proof_dict, indent=4)
    
    # Writing to sample.json
    if sys.argv[5] == "root":
        with open("providers/roots/" + year + "_AMC" + test + "_root" + ".txt", "w") as outfile:
            outfile.write(newtree.root)
    if sys.argv[5] == "proof":
        with open("my_proofs/" + outputname + "_" + year + "_AMC" + test + "_proof" + ".json", "w") as outfile:
            outfile.write(json_object)
    if sys.argv[5] == "root_proof":
        with open("providers/roots/" + year + "_AMC" + test + ".txt", "w") as outfile:
            outfile.write(newtree.root)
        with open("my_proofs/" + outputname + "_" + year + "_AMC" + test + "_proof" + ".json", "w") as outfile:
            outfile.write(json_object)