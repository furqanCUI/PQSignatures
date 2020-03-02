import hashlib
import binascii

def key_gen(seedSource):

    k = bytearray(seedSource,'utf-8')
    seed = hashlib.sha384(k).digest() # The hash of user's provided private key acts as the "seed"

    f_pr_key=[] # generating forward private key
    for i in range(99):
        seed = hashlib.sha384(seed).digest()
        f_pr_key.append(seed)

    b_pr_key=[] # generating backward private key
    for i in range(99):
        seed = hashlib.sha384(seed).digest()
        b_pr_key.append(seed)

    #writing private key (sk) to file
    keyfile = open('confidential.txt','w')
    keyfile.write('Source for seed'+'\n'+seedSource+'\n')
    keyfile.write('\n'+'Forward private key' + '\n')
    for fk in f_pr_key:
        keyfile.write(str(binascii.hexlify(fk),'utf-8')+'\n') # writing forward sk to file
    keyfile.write('\n'+'Backward private key' + '\n')
    for bk in b_pr_key:
        keyfile.write(str(binascii.hexlify(bk), 'utf-8')+'\n') # writing backward sk to file

    f_pub_key=[] # generating forward public key
    for x in f_pr_key:
        x = hashlib.sha384(x).digest()
        for i in range(16):
            y = x[0:48 - i * 3] #applies "substring" operation
            x = hashlib.sha384(y).digest()
        f_pub_key.append(x)

    b_pub_key=[] #generating the backward public key
    for x in b_pr_key:
        x = hashlib.sha384(x).digest()
        for i in range(16):
            y = x[0:48 - i * 3] #applies "substring" operation
            x = hashlib.sha384(y).digest()
        b_pub_key.append(x)

    keyfile.write('\n' + 'Forward public key' + '\n')
    for fk in f_pub_key:
        keyfile.write(str(binascii.hexlify(fk),'utf-8')+'\n') # writing forward pk to file
    keyfile.write('\n'+'Backward public key' + '\n')
    for bk in b_pub_key:
        keyfile.write(str(binascii.hexlify(bk), 'utf-8')+'\n') # writing backward pk to file

    #compressing the public key
    pk = bytearray()
    for i in range(99):
        pk = pk + f_pub_key[i]+ b_pub_key[i]
    ledgerAddress = hashlib.sha384(pk).digest() # hash of compressed public key is the ledger address

    #writing ledger address to the file "LedgerAddress"
    addressfile = open('LedgerAddress.txt','w')
    addressfile.write('Ledger Address'+'\n')
    addressfile.write(str(binascii.hexlify(ledgerAddress), 'utf-8')+'\n')

    keyfile.close()
    addressfile.close()

    print ('Keys written to the file \"confidential\"')
    print('Ledger address written to the file \"ledgerAddress\"')

key_gen('COMSATS') #calling the key-generation function (provide source text for seed as parameter)

