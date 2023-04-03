############################################################
import * as noble from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"

crypto = window.crypto.subtle

ORDER = BigInt(2) ** BigInt(252) + BigInt('27742317777372353535851937790883648493')

############################################################
#region internalFunctions
hashToScalar = (byteBuffer) ->
    relevant = new Uint8Array(byteBuffer.slice(0, 32))
    relevant[0] &= 248
    relevant[31] &= 127
    relevant[31] |= 64
    bigInt = tbut.bytesToBigInt(relevant)
    return mod(bigInt)

mod = (a, b = ORDER) ->
  result = a % b;
  if result >= 0n then return result
  else return result + b

############################################################
createKeyObject = (keyHex) ->
    keyBytes = tbut.hexToBytes(keyHex)
    return await crypto.importKey("raw", keyBytes, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

createKeyObjectHex = createKeyObject

createKeyObjectBytes = (keyBytes) ->
    return await crypto.importKey("raw", keyBytes, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

#endregion

############################################################
#region exposedStuff

############################################################
#region shas

############################################################
# Hex Version
export sha256 = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    hashBytes = await crypto.digest("SHA-256", contentBytes)
    return tbut.bytesToHex(hashBytes)

export sha512 = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    hashBytes = await crypto.digest("SHA-512", contentBytes)
    return tbut.bytesToHex(hashBytes)

export sha256Hex = sha256
export sha512Hex = sha512

############################################################
# Byte Version
export sha256Bytes = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    return new Uint8Array(await crypto.digest("SHA-256", contentBytes))

export sha512Bytes = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    return new Uint8Array(await crypto.digest("SHA-512", contentBytes)) 

#endregion

############################################################
#region keys

############################################################
# Hex Version
export createKeyPair = ->
    secretKeyBytes = noble.utils.randomPrivateKey()
    publicKeyBytes = await noble.getPublicKey(secretKeyBytes)
    secretKeyHex = tbut.bytesToHex(secretKeyBytes)
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return tbut.bytesToHex(keyAndIV)

export createPublicKey = (secretKeyHex) ->
    publicKeyBytes = await noble.getPublicKey(secretKeyHex)
    return tbut.bytesToHex(publicKeyBytes)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey
export createPublicKeyHex = createPublicKey

############################################################
# Byte Version
export createKeyPairBytes = ->
    secretKeyBytes = noble.utils.randomPrivateKey()
    publicKeyBytes = await noble.getPublicKey(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = -> 
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return keyAndIV

export createPublicKeyBytes = (secretKeyBytes) -> await noble.getPublicKey(secretKeyBytes)

#endregion

############################################################
#region signatures

############################################################
# Hex Version
export createSignature = (content, signingKeyHex) ->
    hashHex = await sha256Hex(content)
    signature = await noble.sign(hashHex, signingKeyHex)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    hashHex = await sha256Hex(content)
    return await noble.verify(sigHex, hashHex, keyHex)

export createSignatureHex = createSignature
export verifyHex = verify

############################################################
# Byte Version
export createSignatureBytes = (content, signingKeyBytes) ->
    hashBytes = await sha256Bytes(content)
    return await noble.sign(hashBytes, signingKeyBytes)
    
export verifyBytes = (sigBytes, keyBytes, content) ->
    hashBytes = await sha256Bytes(content)
    return await noble.verify(sigBytes, hashBytes, keyBytes)
#endregion

############################################################
#region symmetric encryption

############################################################
# Hex Version
export symmetricEncrypt = (content, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)

    ivBytes = tbut.hexToBytes(ivHex)
    saltedContent = saltContent(content)

    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObjHex, saltedContent)
    return tbut.bytesToHex(gibbrishBytes)

export symmetricDecrypt = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)
    
    ivBytes = tbut.hexToBytes(ivHex)
    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    
    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    saltedContent = await crypto.decrypt(algorithm, keyObjHex, gibbrishBytes)
    return unsaltContent(saltedContent)

export symmetricEncryptHex = symmetricEncrypt
export symmetricDecryptHex = symmetricDecrypt
############################################################
# Byte Version
export symmetricEncryptBytes = (content, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)

    saltedContent = saltContent(content)

    keyObjBytes = await createKeyObjectBytes(aesKeyBytes)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObjBytes, saltedContent)
    return gibbrishBytes

export symmetricDecryptBytes = (gibbrishBytes, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)
        
    keyObjBytes = await createKeyObjectBytes(aesKeyBytes)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    saltedContent = await crypto.decrypt(algorithm, keyObjBytes, gibbrishBytes)
    return unsaltContent(saltedContent)

#endregion

############################################################
#region Unsalted symmetric encryption

############################################################
# Hex Version
export symmetricEncryptUnsalted = (content, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)

    ivBytes = tbut.hexToBytes(ivHex)
    contentBytes = tbut.utf8ToBytes(content)

    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm = 
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObjHex, contentBytes)
    return tbut.bytesToHex(gibbrishBytes)

export symmetricDecryptUnsalted = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)
    
    ivBytes = tbut.hexToBytes(ivHex)
    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    
    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    contentBytes = await crypto.decrypt(algorithm, keyObjHex, gibbrishBytes)
    return tbut.bytesToUtf8(contentBytes)

#endregion

############################################################
#region asymmetric encryption

############################################################
# Hex Version

############################################################
export asymmetricEncryptOld = (content, publicKeyHex) ->
    # a = Secret Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    
    B = noble.Point.fromHex(publicKeyHex)
    BHex = publicKeyHex
    # log "BHex: " + BHex

    # n = new one-time secret (generated on sever and forgotten about)
    # l = sha512(n) -> hashToScalar
    # lB = lkG = shared secret
    # key = sha512(lBHex)
    # X = symmetricEncrypt(content, key)
    # A = lG = one time public reference point
    # {A,X} = data to be stored for B

    # n = one-time secret
    nBytes = noble.utils.randomPrivateKey()
    nHex = tbut.bytesToHex(nBytes)

    lBigInt = hashToScalar(await sha512Bytes(nBytes))
    
    #A one time public key = reference Point
    ABytes = await noble.getPublicKey(nHex)
    lB = await B.multiply(lBigInt)
    
    symkey = await sha512Hex(lB.toHex())
    
    gibbrish = await  symmetricEncryptHex(content, symkey)
    
    referencePointHex = tbut.bytesToHex(ABytes)
    encryptedContentHex = gibbrish

    return {referencePointHex, encryptedContentHex}

export asymmetricDecryptOld = (secrets, secretKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")
    # a = Secret Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    aBytes = tbut.hexToBytes(secretKeyHex)
    kBigInt = hashToScalar(await sha512Bytes(aBytes))
    
    # {A,X} = secrets
    # A = lG = one time public reference point 
    # klG = lB = kA = shared secret
    # key = sha512(kAHex)
    # content = symmetricDecrypt(X, key)
    A = noble.Point.fromHex(AHex)
    kA = await A.multiply(kBigInt)
    
    symkey = await sha512Hex(kA.toHex())

    content = await symmetricDecryptHex(gibbrishHex,symkey)
    return content

############################################################
export asymmetricEncrypt = (content, publicKeyHex) ->
    nBytes = noble.utils.randomPrivateKey()
    A = await noble.getPublicKey(nBytes)
    lB = await noble.getSharedSecret(nBytes, publicKeyHex)

    symkey = await sha512Bytes(lB)
    
    gibbrish = await symmetricEncryptBytes(content, symkey)    
    
    referencePointHex = tbut.bytesToHex(A)
    encryptedContentHex = tbut.bytesToHex(gibbrish)

    return {referencePointHex, encryptedContentHex}

export asymmetricDecrypt = (secrets, secretKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")

    kA = await noble.getSharedSecret(secretKeyHex, AHex)
    symkey = await sha512Bytes(kA)

    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    content = await symmetricDecryptBytes(gibbrishBytes, symkey)
    return content

export asymmetricEncryptHex = asymmetricEncrypt
export asymmetricDecryptHex = asymmetricDecrypt

############################################################
# Byte Version
export asymmetricEncryptBytes = (content, publicKeyBytes) ->
    nBytes = noble.utils.randomPrivateKey()
    ABytes = await noble.getPublicKey(nBytes)
    lB = await noble.getSharedSecret(nBytes, publicKeyBytes)

    symkeyBytes = await sha512Bytes(lB)
    gibbrishBytes = await symmetricEncryptBytes(content, symkeyBytes)    
    
    referencePointBytes = ABytes
    encryptedContentBytes = gibbrishBytes

    return {referencePointBytes, encryptedContentBytes}

export asymmetricDecryptBytes = (secrets, secretKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    kABytes = await noble.getSharedSecret(secretKeyBytes, ABytes)
    symkeyBytes = await sha512Bytes(kABytes)

    content = await symmetricDecryptBytes(gibbrishBytes, symkeyBytes)
    return content

#endregion

############################################################
#region referenced/shared secrets

############################################################
# Hex Versions

############################################################
export createSharedSecretHash = (secretKeyHex, publicKeyHex, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    
    seedBytes = new Uint8Array(nBBytes.length + cBytes.length)
    l = nBBytes.length
    seedBytes[i] = byte for byte,i in nBBytes
    seedBytes[l+i] = byte for byte,i in cBytes

    sharedSecretBytes = await sha512Bytes(seedBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

export createSharedSecretRaw = (secretKeyHex, publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    sharedSecretBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

export createSharedSecretHashHex = createSharedSecretHash
export createSharedSecretRawHex = createSharedSecretRaw

############################################################
export referencedSharedSecretHash = (publicKeyHex, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    
    seedBytes = new Uint8Array(nBBytes.length + cBytes.length)
    l = nBBytes.length
    seedBytes[i] = byte for byte,i in nBBytes
    seedBytes[l+i] = byte for byte,i in cBytes


    sharedSecretBytes = await sha512Bytes(seedBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export referencedSharedSecretRaw = (publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    sharedSecretBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export referencedSharedSecretHashHex = referencedSharedSecretHash
export referencedSharedSecretRawHex = referencedSharedSecretRaw

############################################################
# Bytes Versions

############################################################
export createSharedSecretHashBytes = (secretKeyBytes, publicKeyBytes, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = secretKeyBytes
    BBytes = publicKeyBytes
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    
    seedBytes = new Uint8Array(nBBytes.length + cBytes.length)
    l = nBBytes.length
    seedBytes[i] = byte for byte,i in nBBytes
    seedBytes[l+i] = byte for byte,i in cBytes


    sharedSecretBytes = await sha512Bytes(seedBytes)

    return sharedSecretBytes

export createSharedSecretRawBytes = (secretKeyBytes, publicKeyBytes) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = secretKeyBytes
    BBytes = publicKeyBytes
    
    sharedSecretBytes = await noble.getSharedSecret(nBytes, BBytes)

    return sharedSecretBytes

############################################################
export referencedSharedSecretHashBytes = (publicKeyBytes, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = publicKeyBytes
    ABytes = await noble.getPublicKey(nBytes)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    
    seedBytes = new Uint8Array(nBBytes.length + cBytes.length)
    l = nBBytes.length
    seedBytes[i] = byte for byte,i in nBBytes
    seedBytes[l+i] = byte for byte,i in cBytes


    sharedSecretBytes = await sha512Bytes(seedBytes)

    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }

export referencedSharedSecretRawBytes = (publicKeyBytes) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = publicKeyBytes
    ABytes = await noble.getPublicKey(nBytes)
    
    sharedSecretBytes = await noble.getSharedSecret(nBytes, BBytes)

    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }


#endregion

############################################################
#region salts
export createRandomLengthSalt = ->
    bytes = new Uint8Array(512)
    loop
        window.crypto.getRandomValues(bytes)
        for byte,i in bytes when byte == 0
            return tbut.bytesToUtf8(bytes.slice(0,i+1))        

export removeSalt = (content) ->
    for char,i in content when char == "\0"
        return content.slice(i+1)
    throw new Error("No Salt termination found!")    

############################################################
export saltContent = (content) ->
    content = tbut.utf8ToBytes(content)
    contentLength = content.length

    sizeRand = Uint8Array[1]
    window.crypto.getRandomValues(sizeRand)
    saltLength = 33 + (sizeRand[0] & 127 )
    salt = new Uint8Array(saltLength)
    window.crypto.getRandomValues(salt)

    # Prefix is salt + 3 bytes
    prefixLength = saltLength + 3
    unpaddedLength = prefixLength + contentLength
    overlap = unpaddedLength % 32
    padding = 32 - overlap

    fullLength = unpaddedLength + padding
    
    resultBytes = new Uint8Array(fullLength)
    # immediatly write the content to the resultBytes
    for c,idx in content
        resultBytes[idx + prefixLength] = c

    # The first 32 bytes of the prefix are 1:1 from the salt.
    sum = 0 
    idx = 32
    while(idx--)
        sum += salt[idx]
        resultBytes[idx] = salt[idx]

    # the last byte of the prefix is the padding length
    resultBytes[saltLength + 2] = padding

    # the padding postfix is the mirrored salt bytes up to padding size
    idx = 0    
    end = fullLength - 1
    while(idx < padding)
        resultBytes[end - idx] = salt[idx]
        idx++

    # the prefix keeps the sum of the salt values as ending identification 
    # make sure this condition is not met before we reach the real end
    idx = 32
    while(idx < saltLength)
        # when the condition is met we add +1 to the LSB(salt[idx+1]) to destroy it 
        # Notice! If we add +1 to the MSB(salt[idx]) then we change what we cheched for previously, which might accidentally result in the condition being met now one byte before, which we donot check for ever again
        # if (sum == (salt[idx]*256 + salt[idx+1])) then salt[idx+1]++
        salt[idx+1] += (sum == (salt[idx]*256 + salt[idx+1]))
        sum += salt[idx]
        resultBytes[idx] = salt[idx]
        idx++

    # save the sum in the right bytes
    resultBytes[saltLength] = (sum >> 8)
    resultBytes[saltLength + 1] = (sum % 256)

    # in this case we have the condition met when just taking the most significatn bytes of the real sum into account
    if resultBytes[saltLength] == resultBytes[saltLength - 1] and resultBytes[saltLength + 1] == 2 * resultBytes[saltLength]
        resultBytes[saltLength - 1]++
        sum++
        resultBytes[saltLength] = (sum >> 8)
        resultBytes[saltLength + 1] = (sum % 256)

    return resultBytes

export unsaltContent = (contentBytes) ->
    fullLength = contentBytes.length

    if fullLength > 160 then limit = 160
    else limit = fullLength
    overLimit = limit + 1

    sum = 0 
    idx = 32
    while(idx--)
        sum += contentBytes[idx]

    idx = 32
    while idx < overLimit
        if (sum == (contentBytes[idx]*256 + contentBytes[idx+1]))
            start = idx + 3
            padding = contentBytes[idx+2]
            break
        sum += contentBytes[idx]
        idx++

    if idx > limit then throw new Error("Unsalt: No valid prefix ending found!")
    

    # Check if the padding matches the salt - so we can verify here nobody has tampered with it
    idx = 0
    end = fullLength - 1
    invalid = 0
    while idx < padding
        invalid += (contentBytes[idx] != contentBytes[end - idx])
        idx++
    if invalid then throw new Error("Unsalt: Postfix and prefix did not match as expected!")
    end = fullLength - padding

    contentBytes = contentBytes.slice(start, end)
    return tbut.bytesToUtf8(contentBytes)

#endregion


#endregion