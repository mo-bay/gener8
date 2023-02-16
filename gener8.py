import ecdsa
import random
import hashlib

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def private_key_to_wif(key_hex):    
    return base58_check_encode(0x38, bytes.fromhex(key_hex))

def private_key_to_public_key(s):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(s), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_addr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(bytes.fromhex(s)).digest())
    return base58_check_encode(0, ripemd160.digest())

def key_to_addr(s):
    return public_key_to_addr(private_key_to_public_key(s).hex())

def base58_encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n //= 58
    return result

def base58_check_encode(version, payload):
    s = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[:4]
    result = s + checksum
    leading_zeros = count_leading_chars(result, b'\0')
    return 'Z' * leading_zeros + base58_encode(base256decode(result))

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + c
    return result

def count_leading_chars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
print('Private key: ', private_key)
pub_key = private_key_to_public_key(private_key)
print('\nPublic key: ', pub_key.hex())
print('\nWIF: ', private_key_to_wif(private_key))
print('\nAddress: ', key_to_addr(private_key))
