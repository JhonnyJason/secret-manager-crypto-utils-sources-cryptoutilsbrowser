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

    ivBuffer = tbut.hexToBytes(ivHex)
    contentBuffer = tbut.utf8ToBytes(content)

    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm = 
        name: "AES-CBC"
        iv: ivBuffer

    gibbrishBuffer = await crypto.encrypt(algorithm, keyObjHex, contentBuffer)
    return tbut.bytesToHex(gibbrishBuffer)

export symmetricDecrypt = (gibbrishHex, keyHex) ->
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

export symmetricEncryptHex = symmetricEncrypt
export symmetricDecryptHex = symmetricDecrypt
############################################################
# Byte Version
export symmetricEncryptBytes = (content, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)

    contentBytes = tbut.utf8ToBytes(content)

    keyObjBytes = await createKeyObjectBytes(aesKeyBytes)
    algorithm = 
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObjBytes, contentBytes)
    return gibbrishBytes

export symmetricDecryptBytes = (gibbrishBytes, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)
        
    keyObjBytes = await createKeyObjectBytes(aesKeyBytes)
    algorithm = 
        name: "AES-CBC"
        iv: ivBytes

    contentBytes = await crypto.decrypt(algorithm, keyObjBytes, gibbrishBytes)
    return tbut.bytesToUtf8(contentBytes)

#endregion

############################################################
#region asymmetric encryption

############################################################
# Hex Version
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

#endregion



############################################################
#region new Functions on v0.2

############################################################
#region referenced/shared secrets

############################################################
#region Hex Versions

############################################################
# create shared secrets
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
# create shared secrets with a new reference point
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
#endregion

############################################################
#region Bytes Versions

############################################################
# create shared secrets
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
# create shared secrets with a new reference point
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

#endregion

############################################################
#region auth code

############################################################
# Hex Version
export authCode = (seedHex, requestJSON) ->
    requestString = JSON.stringify(requestJSON)
    entropySource = seedHex + requestString
    return await sha256Hex(entropySource)
    
export authCodeHex = authCode

############################################################
# Byte Version
export authCodeBytes = (seedBytes, requestJSON) ->
    requestString = JSON.stringify(requestJSON)
    seedHex = tbut.bytesToHex(seedBytes)
    entropySource = seedHex + requestString
    return await sha256Bytes(entropySource)

#endregion

############################################################
#region session key

############################################################
# Hex Version
export sessionKey = (seedHex, requestJSON) ->
    requestString = JSON.stringify(requestJSON)
    entropySource = seedHex+requestString
    return await sha512Hex(entropySource)

export sessionKeyHex = sessionKey

############################################################
# Byte Version
export sessionKeyBytes = (seedBytes, requestJSON) ->
    requestString = JSON.stringify(requestJSON)
    seedHex = tbut.bytesToHex(seedBytes)
    entropySource = seedHex+requestString
    return await sha512Bytes(entropySource)

#endregion

#endregion



#endregion