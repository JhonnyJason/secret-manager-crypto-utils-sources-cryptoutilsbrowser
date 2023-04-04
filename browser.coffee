############################################################
import *  as ed255 from "@noble/ed25519"
import { x25519 as x255 } from "@noble/curves/ed25519"
import * as tbut from "thingy-byte-utils"

############################################################
crypto = window.crypto.subtle

############################################################
#region internalFunctions

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
    secretKeyBytes = ed255.utils.randomPrivateKey()
    publicKeyBytes = await ed255.getPublicKey(secretKeyBytes)
    secretKeyHex = tbut.bytesToHex(secretKeyBytes)
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return tbut.bytesToHex(keyAndIV)

export createPublicKey = (secretKeyHex) ->
    publicKeyBytes = await ed255.getPublicKey(secretKeyHex)
    return tbut.bytesToHex(publicKeyBytes)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey
export createPublicKeyHex = createPublicKey

############################################################
# Byte Version
export createKeyPairBytes = ->
    secretKeyBytes = ed255.utils.randomPrivateKey()
    publicKeyBytes = await ed255.getPublicKey(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = -> 
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return keyAndIV

export createPublicKeyBytes = (secretKeyBytes) -> await ed255.getPublicKey(secretKeyBytes)

#endregion

############################################################
#region signatures

############################################################
# Hex Version
export createSignature = (content, signingKeyHex) ->
    hashHex = await sha256Hex(content)
    signature = await ed255.sign(hashHex, signingKeyHex)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    hashHex = await sha256Hex(content)
    return await ed255.verify(sigHex, hashHex, keyHex)

export createSignatureHex = createSignature
export verifyHex = verify

############################################################
# Byte Version
export createSignatureBytes = (content, signingKeyBytes) ->
    hashBytes = await sha256Bytes(content)
    return await ed255.sign(hashBytes, signingKeyBytes)
    
export verifyBytes = (sigBytes, keyBytes, content) ->
    hashBytes = await sha256Bytes(content)
    return await ed255.verify(sigBytes, hashBytes, keyBytes)
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
    saltedContent = new Uint8Array(saltedContent)
    return unsaltContent(saltedContent)

#endregion

############################################################
#region asymmetric encryption

############################################################
# Hex Version

############################################################
export asymmetricEncrypt = (content, publicKeyHex) ->
    nBytes = ed255.utils.randomPrivateKey()
    A = await ed255.getPublicKey(nBytes)
    lB = await ed255.getSharedSecret(nBytes, publicKeyHex)

    symkey = await sha512Bytes(lB)
    
    gibbrish = await symmetricEncryptBytes(content, symkey)    
    
    referencePointHex = tbut.bytesToHex(A)
    encryptedContentHex = tbut.bytesToHex(gibbrish)

    return {referencePointHex, encryptedContentHex}

export asymmetricDecrypt = (secrets, secretKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")

    kA = await ed255.getSharedSecret(secretKeyHex, AHex)
    symkey = await sha512Bytes(kA)

    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    content = await symmetricDecryptBytes(gibbrishBytes, symkey)
    return content

export asymmetricEncryptHex = asymmetricEncrypt
export asymmetricDecryptHex = asymmetricDecrypt

############################################################
# Byte Version
export asymmetricEncryptBytes = (content, publicKeyBytes) ->
    nBytes = ed255.utils.randomPrivateKey()
    ABytes = await ed255.getPublicKey(nBytes)
    lB = await ed255.getSharedSecret(nBytes, publicKeyBytes)

    symkeyBytes = await sha512Bytes(lB)
    gibbrishBytes = await symmetricEncryptBytes(content, symkeyBytes)    
    
    referencePointBytes = ABytes
    encryptedContentBytes = gibbrishBytes

    return {referencePointBytes, encryptedContentBytes}

export asymmetricDecryptBytes = (secrets, secretKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    kABytes = await ed255.getSharedSecret(secretKeyBytes, ABytes)
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
    
    nBBytes = await ed255.getSharedSecret(nBytes, BBytes)

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
    
    sharedSecretBytes = await ed255.getSharedSecret(nBytes, BBytes)

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
    nBytes = ed255.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await ed255.getPublicKey(nBytes)
    
    nBBytes = await ed255.getSharedSecret(nBytes, BBytes)

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
    nBytes = ed255.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await ed255.getPublicKey(nBytes)
    
    sharedSecretBytes = await ed255.getSharedSecret(nBytes, BBytes)

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
    
    nBBytes = await ed255.getSharedSecret(nBytes, BBytes)

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
    
    sharedSecretBytes = await ed255.getSharedSecret(nBytes, BBytes)

    return sharedSecretBytes

############################################################
export referencedSharedSecretHashBytes = (publicKeyBytes, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = ed255.utils.randomPrivateKey()
    
    BBytes = publicKeyBytes
    ABytes = await ed255.getPublicKey(nBytes)
    
    nBBytes = await ed255.getSharedSecret(nBytes, BBytes)

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
    nBytes = ed255.utils.randomPrivateKey()
    
    BBytes = publicKeyBytes
    ABytes = await ed255.getPublicKey(nBytes)
    
    sharedSecretBytes = await ed255.getSharedSecret(nBytes, BBytes)

    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }


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