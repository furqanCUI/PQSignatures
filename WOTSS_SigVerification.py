import hashlib
import binascii

def trx_sig_verification(trx,sigsFilePath, ledgerAddressFilePath):

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

    sigsFile = open(sigsFilePath,'r')
    sigsFile.readline() # skip first line of the file
    for_sigs = []  # forward signatures
    back_sigs = []  # backward signatures
    for i in range(99): # signatures consists of 198 values in total
        fSigLine = sigsFile.readline()
        fSigLine = fSigLine[:len(fSigLine)-1] # skip the end line character from a signature-value
        bSigLine = sigsFile.readline()
        bSigLine = bSigLine[:len(bSigLine) - 1]  # skip the end line character from a signature-value
        for_sigs.append(binascii.unhexlify(fSigLine))
        back_sigs.append(binascii.unhexlify(bSigLine))
    
    fVerificationKey = []
    bVerificationKey = []

    for i in range(trxhashhex.__len__()):
        fsig = for_sigs[i]
        bsig = back_sigs[i]
        if chr(trxhashhex[i]) == '0':
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '1':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(1):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 15)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '2':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(2):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 14)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '3':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(3):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 13)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '4':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(4):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 12)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '5':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(5):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 11)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '6':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(6):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 10)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '7':
            fsig = hashlib.sha384(fsig).digest()
            for j in range(7):
                bsig = hashlib.sha384(bsig).digest()
                bsig = bsig[0:48 - 3 * (j + 9)]
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '8':
            for j in range(7):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 9)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == '9':
            for j in range(6):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 10)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == 'a':
            for j in range(5):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 11)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == 'b':
            for j in range(4):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 12)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == 'c':
            for j in range(3):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 13)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == 'd':
            for j in range(2):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 14)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex[i]) == 'e':
            for j in range(1):
                fsig = hashlib.sha384(fsig).digest()
                fsig = fsig[0:48 - 3 * (j + 15)]
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()
        elif chr(trxhashhex [i]) == 'f':
            fsig = hashlib.sha384(fsig).digest()
            bsig = hashlib.sha384(bsig).digest()

        fVerificationKey.append(fsig)
        bVerificationKey.append(bsig)

    # compressing the verification key to find the uesr address
    verKey = bytearray()
    for i in range(99):
        verKey = verKey + fVerificationKey[i]+ bVerificationKey[i]
    userAddress = hashlib.sha384(verKey).digest() # hash of compressed public key is the ledger address
    userAddressSTR = str(binascii.hexlify(userAddress),'utf-8')

    # reading ledger address from the file
    ledgerAddressFile = open(ledgerAddressFilePath,'r')
    ledgerAddressFile.readline() # skip line
    ledgerAddress = ledgerAddressFile.readline()
    ledgerAddress = ledgerAddress[:len(ledgerAddress)-1] # truncate end-line character from ledger address

    #verifying the user address
    if ledgerAddress == userAddressSTR:
        print('Transaction signatures successfully verified')
    else:
        print('Transaction signatures are invalid')

    sigsFile.close()
    ledgerAddressFile.close()
#calling the trx-signature verification function (provide three parameter:
# transaction to be signed, path of the file containing signatures, and path of file containing the ledger address)
trx_sig_verification('From:me To:boss coins:5 date:28-02-2020 time:17:11','signatures.txt', 'ledgerAddress.txt')
