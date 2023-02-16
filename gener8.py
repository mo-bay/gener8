import ecdsa
import random
import hashlib

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def privateKeyToWif(key_hex, prefix):
    return base58CheckEncode(prefix, key_hex.decode('hex'))

def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

def pubKeyToAddr(s, prefix):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(prefix, ripemd160.digest())

def keyToAddr(s, prefix):
    return pubKeyToAddr(privateKeyToPublicKey(s), prefix)

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n //= 58
    return result

def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')

    return 'Z' * leadingZeros + base58encode(base256decode(result))

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

def generateKeys(prefix_private, prefix_public):
    private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
    print('Private key: {}'.format(private_key))
    public_key = privateKeyToPublicKey(private_key)
    print('Public key: {}'.format(public_key))
    wif_key = privateKeyToWif(private_key, prefix_private)
    print('WIF key: {}'.format(wif_key))
    address = keyToAddr(private_key, prefix_public)
    print('Address: {}'.format(address))

if __name__ == '__main__':
    prefix_private = int(input("Enter the decimal prefix for the private key: "))
    prefix_public = int(input("Enter the decimal prefix for the public address: "))
    generateKeys(prefix_private, prefix_public)
