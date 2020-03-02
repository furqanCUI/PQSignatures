# PQSignatures
Post-Quantum Digital Signatures
## WOTS-S [Winternitz One-Time Signatures - Short signatures (compact) variant]
###### The corresponding arcticle is under review of the Elsevier Journal "Information Sciences"
---
---
#### The code consists of three Python files, namely: *WOTSS_keygen*, *WOTSS_TrxSigning*, and *WOTSS_SigVerification*
---
#### *WOTSS_keygen* creates a key-pair
- The corresponding function namely *key_gen()* gets a text-value as parameters, which is used to generate *seed* for private key
- *key_gen* creates two text files namely, *confidential.txt* and *LedgerAddress.txt*
- *confidential.txt* contains source-text of seed and the private/public keys
- *LedgerAddress.txt* contains the compressed public key (i.e. the ledger address)
---
#### *WOTSS_TrxSigning* creates signatures on a transaction
- The corresponding function namely *trx_signing()* gets two parameter, 1) transaction to be signed, *and* 2) path of the confidential file
- *trx_signing()* reads source-text of seed from "confidential" file to generate the private key, *then*
- It creates signatures on the transaction (received as argument) and writes signatures in the file *signatures.txt*
---
#### *WOTSS_SigVerification* verifies signatures of the transaction
- The corresponding function namely *trx_sig_verification()* gets three parameter, 1) transaction to be verified, 2) path of the signatures file, *and* 3) path of the "ledger address" file
- It displays the results of verification either on screen either "successful" or "failed" 
