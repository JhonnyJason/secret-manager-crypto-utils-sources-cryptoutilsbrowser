############################################################
import *  as ed255 from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"

############################################################
crypto = window.crypto.subtle

############################################################
ORDER = BigInt(2) ** BigInt(252) + BigInt('27742317777372353535851937790883648493')



############################################################
#region internalFunctions

createKeyObject = (keyHex) ->
    keyBytes = tbut.hexToBytes(keyHex)
    return await crypto.importKey("raw", keyBytes, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

createKeyObjectHex = createKeyObject

createKeyObjectBytes = (keyBytes) ->
    return await crypto.importKey("raw", keyBytes, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

############################################################
hashToScalar = (hash) ->
    relevant = hash.slice(0, 32)
    relevant[0] &= 248
    relevant[31] &= 127
    relevant[31] |= 64
    bigInt = tbut.bytesToBigInt(relevant)
    return mod(bigInt)

mod = (a, b = ORDER) ->
  result = a % b;
  if result >= 0n then return result
  else return result + b

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
    secretKeyBytes = ed255.utils.randomPrivateKey()
    publicKeyBytes = await ed255.getPublicKeyAsync(secretKeyBytes)
    secretKeyHex = tbut.bytesToHex(secretKeyBytes)
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return tbut.bytesToHex(keyAndIV)

export createPublicKey = (secretKeyHex) ->
    publicKeyBytes = await ed255.getPublicKeyAsync(secretKeyHex)
    return tbut.bytesToHex(publicKeyBytes)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey
export createPublicKeyHex = createPublicKey

############################################################
# Byte Version
export createKeyPairBytes = ->
    secretKeyBytes = ed255.utils.randomPrivateKey()
    publicKeyBytes = await ed255.getPublicKeyAsync(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = ->
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return keyAndIV

export createPublicKeyBytes = (secretKeyBytes) -> await ed255.getPublicKeyAsync(secretKeyBytes)

#endregion

############################################################
#region signatures

############################################################
# Hex Version
export createSignature = (content, signingKeyHex) ->
    contentBytes = tbut.utf8ToBytes(content)
    signingKeyBytes = tbut.hexToBytes(signingKeyHex)
    signature = await ed255.signAsync(contentBytes, signingKeyBytes)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    sigBytes = tbut.hexToBytes(sigHex)
    keyBytes = tbut.hexToBytes(keyHex)
    contentBytes = tbut.utf8ToBytes(content)
    return await ed255.verifyAsync(sigBytes, contentBytes, keyBytes)

export createSignatureHex = createSignature
export verifyHex = verify 
############################################################
# Byte Version
export createSignatureBytes = (content, signingKeyBytes) ->
    contentBytes = tbut.utf8ToBytes(content)
    return await ed255.signAsync(contentBytes, signingKeyBytes)

export verifyBytes = (sigBytes, keyBytes, content) ->
    contentBytes = tbut.utf8ToBytes(content)
    return await ed255.verifyAsync(sigBytes, contentBytes, keyBytes)


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

    keyObj = await createKeyObjectHex(aesKeyHex)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObj, saltedContent)
    return tbut.bytesToHex(gibbrishBytes)

export symmetricDecrypt = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)
    
    ivBytes = tbut.hexToBytes(ivHex)
    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    
    keyObj = await createKeyObjectHex(aesKeyHex)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    saltedContent = await crypto.decrypt(algorithm, keyObj, gibbrishBytes)
    saltedContent = new Uint8Array(saltedContent)
    return unsaltContent(saltedContent)

export symmetricEncryptHex = symmetricEncrypt
export symmetricDecryptHex = symmetricDecrypt
############################################################
# Byte Version
export symmetricEncryptBytes = (content, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)

    saltedContent = saltContent(content)

    keyObj = await createKeyObjectBytes(aesKeyBytes)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObj, saltedContent)
    return gibbrishBytes

export symmetricDecryptBytes = (gibbrishBytes, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)
        
    keyObj = await createKeyObjectBytes(aesKeyBytes)
    algorithm =
        name: "AES-CBC"
        iv: ivBytes

    saltedContent = await crypto.decrypt(algorithm, keyObj, gibbrishBytes)
    saltedContent = new Uint8Array(saltedContent)
    return unsaltContent(saltedContent)

#endregion

############################################################
#region asymmetric encryption

############################################################
# Hex Version

############################################################
export asymmetricEncrypt = (content, publicKeyHex) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(await sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    
    # encrypt with symmetricEncryptHex
    symkeyHex = await sha512Hex(lB.toRawBytes())    
    gibbrishHex = await symmetricEncryptHex(content, symkeyHex)

    referencePointHex = tbut.bytesToHex(ABytes)
    encryptedContentHex = gibbrishHex
    return {referencePointHex, encryptedContentHex}


export asymmetricDecrypt = (secrets, secretKeyHex) ->
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
    A = ed255.ExtendedPoint.fromHex(AHex)
    kA = A.multiply(kBigInt)

    symkeyHex = await sha512Hex(kA.toRawBytes())
    content = await symmetricDecryptHex(gibbrishHex,symkeyHex)
    return content

export asymmetricEncryptHex = asymmetricEncrypt
export asymmetricDecryptHex = asymmetricDecrypt

############################################################
# Byte Version
export asymmetricEncryptBytes = (content, publicKeyBytes) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)
    
    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(await sha512Bytes(nBytes))

    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)

    symkeyBytes = await sha512Bytes(lB.toRawBytes())
    gibbrishBytes = await symmetricEncryptBytes(content, symkeyBytes)

    referencePointBytes = ABytes
    encryptedContentBytes = gibbrishBytes
    return {referencePointBytes, encryptedContentBytes}

export asymmetricDecryptBytes = (secrets, secretKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    # a = Secret Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    kBigInt = hashToScalar(await sha512Bytes(secretKeyBytes))

    # {A,X} = secrets
    # A = lG = one time public reference point 
    # klG = lB = kA = shared secret
    # key = sha512(kAHex)
    # content = symmetricDecrypt(X, key)
    AHex = tbut.bytesToHex(ABytes)
    A = ed255.ExtendedPoint.fromHex(AHex)
    kA = A.multiply(kBigInt)

    symkeyBytes = await sha512Bytes(kA.toRawBytes())
    content = await symmetricDecryptBytes(gibbrishBytes, symkeyBytes)
    return content

#endregion

############################################################
#region deffieHellman/ElGamal secrets

############################################################
# Hex Versions

############################################################
export diffieHellmanSecretHash = (secretKeyHex, publicKeyHex, contextString = "") ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    aBytes = tbut.hexToBytes(secretKeyHex)
    kBigInt = hashToScalar(await sha512Bytes(aBytes))
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)
    
    # A reference Point
    kB = B.multiply(kBigInt)
    kBBytes = kB.toRawBytes()
    cBytes = tbut.utf8ToBytes(contextString)

    seedBytes = new Uint8Array(kBBytes.length + cBytes.length)
    for b,i in kBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[kBBytes.length + i] = b

    sharedSecretHex = await sha512Hex(seedBytes)
    return sharedSecretHex

export diffieHellmanSecretHashHex = diffieHellmanSecretHash
export createSharedSecretHash = diffieHellmanSecretHash
export createSharedSecretHashHex = diffieHellmanSecretHash


export diffieHellmanSecretRaw = (secretKeyHex, publicKeyHex) ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    aBytes = tbut.hexToBytes(secretKeyHex)
    kBigInt = hashToScalar(await sha512Bytes(aBytes))
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)
    
    kB = B.multiply(kBigInt)

    sharedSecretBytes = kB.toRawBytes()
    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

export diffieHellmanSecretRawHex = diffieHellmanSecretRaw
export createSharedSecretRaw = diffieHellmanSecretRaw
export createSharedSecretRawHex = diffieHellmanSecretRaw


############################################################
export elGamalSecretHash = (publicKeyHex, contextString = "") ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(await sha512Bytes(nBytes))

    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()

    cBytes = tbut.utf8ToBytes(contextString)

    seedBytes = new Uint8Array(lBBytes.length + cBytes.length)
    for b,i in lBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[lBBytes.length + i] = b

    sharedSecretHex = await sha512Hex(seedBytes)
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export elGamalSecretHashHex = elGamalSecretHash
export referencedSharedSecretHash = elGamalSecretHash
export referencedSharedSecretHashHex = elGamalSecretHash
export referencedSecretHash = elGamalSecretHash
export referencedSecretHashHex = elGamalSecretHash


export elGamalSecretRaw = (publicKeyHex) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(await sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()
    
    sharedSecretHex = tbut.bytesToHex(lBBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export elGamalSecretRawHex = elGamalSecretRaw
export referencedSharedSecretRaw = elGamalSecretRaw
export referencedSharedSecretRawHex = elGamalSecretRaw
export referencedSecretRaw = elGamalSecretRaw
export referencedSecretRawHex = elGamalSecretRaw


############################################################
# Bytes Versions

############################################################
export diffieHellmanSecretHashBytes = (secretKeyBytes, publicKeyBytes, contextString = "") ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)
    # k 
    kBigInt = hashToScalar(await sha512Bytes(secretKeyBytes))
    # kB = klG = shared Secret
    kB = B.multiply(kBigInt)
    kBBytes = kB.toRawBytes()
    cBytes = tbut.utf8ToBytes(contextString)
    
    seedBytes = new Uint8Array(kBBytes.length + cBytes.length)
    for b,i in kBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[kBBytes.length + i] = b

    sharedSecretBytes = await sha512Bytes(seedBytes)
    return sharedSecretBytes

export sharedSecretHashBytes = diffieHellmanSecretHashBytes


export diffieHellmanSecretRawBytes = (secretKeyBytes, publicKeyBytes) ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)
    # k 
    kBigInt = hashToScalar(await sha512Bytes(secretKeyBytes))
    # kB = klG = shared Secret
    kB = B.multiply(kBigInt)
    kBBytes = kB.toRawBytes()
    return kBBytes

export sharedSecretRawBytes = diffieHellmanSecretRawBytes


############################################################
export elGamalSecretHashBytes = (publicKeyBytes, contextString = "") ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(await sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()

    cBytes = tbut.utf8ToBytes(contextString)

    seedBytes = new Uint8Array(lBBytes.length + cBytes.length)
    for b,i in lBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[lBBytes.length + i] = b
    
    sharedSecretBytes = await sha512Bytes(seedBytes)
    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }

export referencedSharedSecretHashBytes = elGamalSecretHashBytes
export referencedSecretHashBytes = elGamalSecretHashBytes


export elGamalSecretRawBytes = (publicKeyBytes) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)
    
    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(await sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()

    sharedSecretBytes = lBBytes
    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }

export referencedSharedSecretRawBytes = elGamalSecretRawBytes
export referencedSecretRawBytes = elGamalSecretRawBytes


#endregion

############################################################
#region salts
export saltContent = (content) ->
    content = tbut.utf8ToBytes(content)
    contentLength = content.length

    sizeRand = new Uint8Array(1)
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