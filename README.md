# AMC-Score-Prover
To clone this repo locally, run either of the following commands:
* ```git clone https://github.com/MonkeyKing-1/AMC-Score-Prover.git```  
* ```git clone git@github.com:MonkeyKing-1/AMC-Score-Prover.git```  

Within the directory that the repo lives, here are the basic commands:
* To generate the root for a test, run the following command:  
    ```bash proof_gen.sh <year> <test> <fileid> <index> root```  
    `test` and `fileid` can be any dummy value here.
* To generate a proof (non-zk) for a test, run the following command:  
    ```bash proof_gen.sh <year> <test> <fileid> <index> proof```  
    A file named `<fileid>_<year>_AMC<test>_proof.json` will be generated in the `my_proofs` folder.
* To generate the proving and verifying key for the zk proof, run the following command:  
    ```bash verify_proof.sh <year> <test> <fileid> keygen```  
    `year`, `test`, and `fileid` can be any dummy value here.
* To generate a zk snark from the json we just generated, run the following command:  
    ```bash verify_proof.sh <year> <test> <fileid> prove```  
    A file named `<fileid>_<year>_AMC<test>_proof.snark` will be generated in the `my_proofs` folder.
* To verify a zk snark, run the following command:  
    ```bash verify_proof.sh <year> <test> <fileid> prove```
* To do both at the same time, run the following command:  
    ```bash verify_proof.sh <year> <test> <fileid> proverify```

Note that they keygen only needs to be run once, because the circuit is designed to handle all realistic uses.  

Here are some precalculated merkle roots for select AMC contests:
* 2018 AMC 10A: `0x394e3cef59a1175f578d34d5b260ebd77cae4e84fa6105f543db4279cf8825f8`
* 2021 AMC 12A: `0x82651253814a633beb4be2bb252418060a1364ba5873bdbe47f088e143d33f05`

Commands are only synced for Dist Honor Roll, feel free to change the command structure to fix this.
To prove scores for other contests, upload the corresponding csv file into `providers/data` and name it  
```<year> AMC<test> Dist Honor Roll.csv```.

Built from halo2-scaffold:
<https://github.com/axiom-crypto/halo2-scaffold>
