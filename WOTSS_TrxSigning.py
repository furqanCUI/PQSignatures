import hashlib
import binascii

def trx_signing(trx,confidentialFilePath):
    keyfile = open(confidentialFilePath,'r')
    keyfile.readline() # skip first line of the file
    seedSource = keyfile.readline() # read source text of seed from the file
    seedSource = seedSource[:len(seedSource)-1] # truncate new line character from seedSource
    k = bytearray(seedSource,'utf-8') # transform text to bytes
    seed = hashlib.sha384(k).digest()# generate seed from seedSource

    #generate private key from seed
    f_pr_key=[] # generating forward private key
    for i in range(99):
        seed = hashlib.sha384(seed).digest()
        f_pr_key.append(seed)

    b_pr_key=[] # generating backward private key
    for i in range(99):
        seed = hashlib.sha384(seed).digest()
        b_pr_key.append(seed)

    trxbin = bytearray(trx, 'utf-8') # convert transaction to binary form
    trxhash = hashlib.sha384(trxbin).digest() # compute hash of the transaction
    trxhashhex = binascii.hexlify(trxhash) # get hexadecimal representation of the hash of transaction

    # computing checksum on transaction hash
    checksum = 0
    for i in trxhashhex:
        if chr(i) == '0':
            checksum = checksum + (15 - 0)
        elif chr(i) == '1':
            checksum = checksum + (15 - 1)
        elif chr(i) == '2':
            checksum = checksum + (15 - 2)
        elif chr(i) == '3':
            checksum = checksum + (15 - 3)
        elif chr(i) == '4':
            checksum = checksum + (15 - 4)
        elif chr(i) == '5':
            checksum = checksum + (15 - 5)
        elif chr(i) == '6':
            checksum = checksum + (15 - 6)
        elif chr(i) == '7':
            checksum = checksum + (15 - 7)
        elif chr(i) == '8':
            checksum = checksum + (15 - 8)
        elif chr(i) == '9':
            checksum = checksum + (15 - 9)
        elif chr(i) == 'a':
            checksum = checksum + (15 - 10)
        elif chr(i) == 'b':
            checksum = checksum + (15 - 11)
        elif chr(i) == 'c':
            checksum = checksum + (15 - 12)
        elif chr(i) == 'd':
            checksum = checksum + (15 - 13)
        elif chr(i) == 'e':
            checksum = checksum + (15 - 14)
        elif chr(i) == 'f':
            checksum = checksum + (15 - 15)

    trxhashhex = trxhashhex + bytearray(format(checksum, '02x'), 'utf-8') # appends checksum to hash of transaction

    for_sigs = [] # forward signatures
    back_sigs = [] # backward signatures
    for_key = bytearray #variable used during computation of forward signatures
    back_key = bytearray #variable used during computation of backward signatures

    for i in range(trxhashhex.__len__()):

        if chr(trxhashhex[i]) == '0':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15): # creating forward signatures
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)] # applying substring operation
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15): # creating backward signatures
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '1':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(14):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '2':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(13):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '3':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(12):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '4':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(11):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '5':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(10):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '6':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(9):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '7':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(8):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '8':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(8):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == '9':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(9):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == 'a':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(10):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == 'b':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(11):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == 'c':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(12):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == 'd':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(13):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == 'e':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(14):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        elif chr(trxhashhex[i]) == 'f':
            for_key = f_pr_key[i]
            for_key = hashlib.sha384(for_key).digest()
            for j in range(15):
                for_key = hashlib.sha384(for_key).digest()
                for_key = for_key[0:48 - 3 * (j + 1)]
            back_key = b_pr_key[i]
            back_key = hashlib.sha384(back_key).digest()
            for j in range(15):
                back_key = hashlib.sha384(back_key).digest()
                back_key = back_key[0:48 - 3 * (j + 1)]

        for_sigs.append(for_key)
        back_sigs.append(back_key)

    sigsFile = open('signatures.txt','w')
    sigsFile.write('Signatures'+'\n')
    for i in range(99):
        sigsFile.write(str(binascii.hexlify(for_sigs[i]),'utf-8')+'\n')
        sigsFile.write(str(binascii.hexlify(back_sigs[i]), 'utf-8') + '\n')
    keyfile.close()
    sigsFile.close()

    print('Signatures created and stored in the file \"Signatures.txt\"')
#calling the trx-signing function (provide two parameter, transaction to be signed and path of the confidential file)
trx_signing('From:me To:boss coins:5 date:28-02-2020 time:17:11','confidential.txt')
