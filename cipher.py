from abc import ABC, abstractmethod
import string
from typing import Dict, Union
import math
import itertools
import time
import sys
from functools import wraps
import psutil  
import tracemalloc
import os
import random
import math
from typing import Tuple
import hashlib 


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Расширенный алгоритм Евклида"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_prime(n: int, k: int = 128) -> bool:
    """Проверка простоты числа тестом Миллера-Рабина"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
 
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
 
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Общий интерфейс
class Cipher(ABC):
    @abstractmethod
    def encrypt(self, text: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, text: str) -> str:
        pass

class BruteForceAttack(ABC):
    @abstractmethod
    def crack(self, ciphertext: str) -> Dict[Union[int, bytes, str], str]:
        pass
 
def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a: int, m: int) -> int:
    """Модульная обратная величина (обратное по модулю)"""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n: int) -> bool:
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    for i in range(3, int(n**0.5)+1, 2):
        if n % i == 0:
            return False
    return True

def generate_prime(start: int = 100, end: int = 300) -> int:
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

class RSACipher(Cipher):
    def __init__(self, p: int = 61, q: int = 53, e: int = 17):
        if not (is_prime(p) and is_prime(q)):
            raise ValueError("p and q must be prime numbers")
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        
        if gcd(e, self.phi) != 1:
            raise ValueError("e must be coprime with phi(n)")
        self.e = e
        self.d = modinv(e, self.phi)

    def _process_text(self, text: str, power: int, mod: int) -> str:
        try:
            if power == self.e:  # Шифрование
                return " ".join(str(pow(ord(c), power, mod)) for c in text)
            else:  # Дешифрование
                parts = text.split()
                return "".join(chr(pow(int(c), power, mod)) for c in parts)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Processing error: {str(e)}")

    def encrypt(self, text: str) -> str:
        return self._process_text(text, self.e, self.n)

    def decrypt(self, text: str) -> str:
        return self._process_text(text, self.d, self.n)

 
class RSACipherMod(RSACipher):
    def __init__(self):
        super().__init__()
 
        self.p2, self.q2 = 47, 59
        self.n2 = self.p2 * self.q2
        self.phi2 = (self.p2 - 1) * (self.q2 - 1)
        self.e2 = 13
        self.d2 = modinv(self.e2, self.phi2)

    def encrypt(self, text: str) -> str:
 
        first_pass_nums = [pow(ord(c), self.e, self.n) for c in text]
 
        second_pass_nums = [pow(num, self.e2, self.n2) for num in first_pass_nums]
 
        return " ".join(str(num) for num in second_pass_nums)

    def decrypt(self, text: str) -> str:
 
        second_pass_nums = list(map(int, text.split()))
 
        first_pass_nums = [pow(num, self.d2, self.n2) for num in second_pass_nums]
 
        decrypted_chars = [chr(pow(num, self.d, self.n)) for num in first_pass_nums]
        return "".join(decrypted_chars)

 
class CaesarCipher(Cipher):
    def __init__(self, shift: int = 3):
        if not isinstance(shift, int):
            raise ValueError("Shift must be an integer")
        self.shift = shift % 26  

    def encrypt(self, text: str) -> str:
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
            
        result = []
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                shifted = (ord(c) - base + self.shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(c)
        return "".join(result)

    def decrypt(self, text: str) -> str:
        return CaesarCipher(-self.shift).encrypt(text)

 
class CaesarCipherMod(Cipher):
    def __init__(self, key: str = "key"):
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
            
 
        self.key = [ord(c.lower()) - ord('a') for c in key.lower() if c.isalpha()]
        if not self.key:
            self.key = [3]
             
    def _process_text(self, text: str, mode: int) -> str:
        result = []
        key_len = len(self.key)
        idx = 0
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                shift = self.key[idx % key_len] * mode
                shifted = (ord(c) - base + shift) % 26 + base
                result.append(chr(shifted))
                idx += 1
            else:
                result.append(c)
        return "".join(result)

    def encrypt(self, text: str) -> str:
        return self._process_text(text, 1)

    def decrypt(self, text: str) -> str:
        return self._process_text(text, -1)

 
class DESCipher(Cipher):
 
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

 
    IP_INV = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    # Расширение E (32 бита -> 48 бит)
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # S-блоки
    S_BOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

 
    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]

    def __init__(self, key: bytes = b"8bytekey"):
        if not isinstance(key, bytes) or len(key) < 8:
            raise ValueError("Key must be at least 8 bytes")
        self.key = key[:8]   
        self.subkeys = self._generate_subkeys()

    def _permute(self, block: int, table: list, size: int) -> int:
        result = 0
        for i, pos in enumerate(table):
            if block & (1 << (size - pos)):
                result |= (1 << (len(table) - 1 - i))
        return result

    def _generate_subkeys(self) -> list:
 
        pc1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]

 
        pc2 = [
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ]

 
        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

 
        key = int.from_bytes(self.key, byteorder='big')

 
        key = self._permute(key, pc1, 64)

 
        c = (key >> 28) & 0x0FFFFFFF
        d = key & 0x0FFFFFFF

        subkeys = []
        for shift in shifts:
 
            c = ((c << shift) & 0x0FFFFFFF) | (c >> (28 - shift))
            d = ((d << shift) & 0x0FFFFFFF) | (d >> (28 - shift))

 
            cd = (c << 28) | d
            subkey = self._permute(cd, pc2, 56)
            subkeys.append(subkey)

        return subkeys

    def _feistel(self, r: int, subkey: int) -> int:
 
        e = self._permute(r, self.E, 32)

 
        x = e ^ subkey

 
        result = 0
        for i in range(8):
 
            bits = (x >> (42 - 6 * i)) & 0x3F
            row = ((bits & 0x20) >> 4) | (bits & 0x01)
            col = (bits >> 1) & 0x0F
            val = self.S_BOXES[i][row][col]
            result = (result << 4) | val

 
        return self._permute(result, self.P, 32)

    def _process_block(self, block: int, decrypt: bool = False) -> int:
 
        block = self._permute(block, self.IP, 64)

 
        l = (block >> 32) & 0xFFFFFFFF
        r = block & 0xFFFFFFFF

 
        for i in range(16):
            next_l = r
            if decrypt:
 
                r = l ^ self._feistel(r, self.subkeys[15 - i])
            else:
                r = l ^ self._feistel(r, self.subkeys[i])
            l = next_l

 
        combined = (r << 32) | l

 
        return self._permute(combined, self.IP_INV, 64)

    def encrypt(self, text: str) -> str:
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

 
        text_bytes = text.encode('utf-8')
        pad_len = (8 - (len(text_bytes) % 8)) % 8
        text_bytes += bytes([pad_len] * pad_len)

 
        encrypted = bytearray()
        for i in range(0, len(text_bytes), 8):
            block = int.from_bytes(text_bytes[i:i+8], byteorder='big')
            encrypted_block = self._process_block(block)
            encrypted.extend(encrypted_block.to_bytes(8, byteorder='big'))

        return encrypted.hex()

    def decrypt(self, text: str) -> str:
        try:
            data = bytes.fromhex(text)
        except ValueError:
            raise ValueError("Invalid hex string for decryption")

 
        decrypted = bytearray()
        for i in range(0, len(data), 8):
            block = int.from_bytes(data[i:i+8], byteorder='big')
            decrypted_block = self._process_block(block, decrypt=True)
            decrypted.extend(decrypted_block.to_bytes(8, byteorder='big'))

 
        pad_len = decrypted[-1]
        if pad_len > 8:
            pad_len = 0
        return decrypted[:-pad_len].decode('utf-8', errors='ignore')

class DESCipherMod(DESCipher):
    def __init__(self, key: bytes = b"8bytekey", dynamic_rounds: int = 16):
        super().__init__(key)
        self.dynamic_rounds = dynamic_rounds
        self.round_keys = self._generate_dynamic_round_keys()

    def _generate_dynamic_round_keys(self) -> list:
        """Генерирует уникальные ключи для каждого раунда на основе основного ключа"""
        round_keys = []
        key = self.key
        
        for i in range(self.dynamic_rounds):
 
            if i % 3 == 0:
 
                shift = (i + 1) % len(key)
                modified_key = key[shift:] + key[:shift]
            elif i % 3 == 1:
 
                modified_key = bytes([b ^ 0xFF for b in key])
            else:
 
                modified_key = bytes([b ^ i for b in key])
            
 
            temp_cipher = DESCipher(modified_key)
            round_keys.append(temp_cipher.subkeys[i % 16])  
            
        return round_keys

    def _feistel(self, r: int, round_num: int) -> int:
        """Модифицированная функция Фейстеля с динамическим ключом"""
 
        e = self._permute(r, self.E, 32)

 
        x = e ^ self.round_keys[round_num % self.dynamic_rounds]

 
        result = 0
        for i in range(8):
            bits = (x >> (42 - 6 * i)) & 0x3F
            row = ((bits & 0x20) >> 4) | (bits & 0x01)
            col = (bits >> 1) & 0x0F
            val = self.S_BOXES[i][row][col]
            result = (result << 4) | val
 
        return self._permute(result, self.P, 32)

    def _process_block(self, block: int, decrypt: bool = False) -> int:
        """Обработка блока с модифицированными раундами"""
        block = self._permute(block, self.IP, 64)
        l = (block >> 32) & 0xFFFFFFFF
        r = block & 0xFFFFFFFF

 
        rounds = range(self.dynamic_rounds) if not decrypt else reversed(range(self.dynamic_rounds))
        
        for i in rounds:
            next_l = r
            r = l ^ self._feistel(r, i)
            l = next_l

        combined = (r << 32) | l
        return self._permute(combined, self.IP_INV, 64)

    def encrypt(self, text: str) -> str:
        """Шифрование с добавлением IV для CBC режима"""
        iv = os.urandom(8)  
        text_bytes = text.encode('utf-8')
        pad_len = (8 - (len(text_bytes) % 8)) % 8
        text_bytes += bytes([pad_len] * pad_len)

        encrypted = bytearray()
        prev_block = int.from_bytes(iv, byteorder='big')
        
        for i in range(0, len(text_bytes), 8):
            block = int.from_bytes(text_bytes[i:i+8], byteorder='big')
 
            block ^= prev_block
            encrypted_block = self._process_block(block)
            encrypted.extend(encrypted_block.to_bytes(8, byteorder='big'))
            prev_block = encrypted_block

        return iv.hex() + encrypted.hex()

    def decrypt(self, text: str) -> str:
        """Дешифрование с учетом CBC режима"""
        try:
            data = bytes.fromhex(text)
            iv = data[:8]
            data = data[8:]
        except ValueError:
            raise ValueError("Invalid hex string for decryption")

        decrypted = bytearray()
        prev_block = int.from_bytes(iv, byteorder='big')
        
        for i in range(0, len(data), 8):
            block = int.from_bytes(data[i:i+8], byteorder='big')
            decrypted_block = self._process_block(block, decrypt=True)
 
            decrypted_block ^= prev_block
            decrypted.extend(decrypted_block.to_bytes(8, byteorder='big'))
            prev_block = block

        pad_len = decrypted[-1]
        if pad_len > 8:
            pad_len = 0
        return decrypted[:-pad_len].decode('utf-8', errors='ignore')
import random
from typing import Tuple

 
def modinv(a: int, m: int) -> int:
    def egcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return (b, 0, 1)
        else:
            g, x1, y1 = egcd(b % a, a)
            g, x, y = g, y1 - (b // a) * x1, x1
            return g, x, y

    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m
 


def measure_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
 
        process = psutil.Process()
        start_mem = process.memory_info().rss
        tracemalloc.start()

        start_time = time.time()
        iterations = [0]  
        
        def increment_iterations():
            iterations[0] += 1
 
        if 'iteration_callback' not in kwargs:
            kwargs['iteration_callback'] = increment_iterations
        
        result = func(*args, **kwargs)
        result_new = {}
        result_new["results"]=result
        
        end_time = time.time()
 
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop() 
        metrics = {}
        metrics["time"]=end_time - start_time 
        metrics["iterations"]=iterations[0]
        metrics["memory"]=peak
        result_new["metrics"] = metrics
        return result_new
    return wrapper

class CaesarBruteForce(BruteForceAttack):
    def __init__(self, max_shift: int = 25):
        self.max_shift = max_shift

    @measure_performance
    def crack(self, ciphertext: str, iteration_callback=None) -> Dict[int, str]:
        if not isinstance(ciphertext, str):
            raise ValueError("Ciphertext must be a string")
            
        results = {}
        cipher = CaesarCipher()
        
        for shift in range(1, self.max_shift + 1):
            if iteration_callback:
                iteration_callback()
            cipher.shift = shift
            results[shift] = cipher.decrypt(ciphertext)
        
        return results

class CaesarCipherModBruteForce(BruteForceAttack):
    def __init__(self, max_key_length: int = 3):
        self.max_key_length = max_key_length 

    @measure_performance
    def crack(self, ciphertext: str, iteration_callback=None) -> Dict[str, str]:
        results = {}
        
 
 
        if not results:
            for length in range(1, self.max_key_length + 1):
                for letters in itertools.product(string.ascii_lowercase, repeat=length):
                    if iteration_callback:
                        iteration_callback()
                    key = ''.join(letters)
                    cipher = CaesarCipherMod(key)
                    decrypted = cipher.decrypt(ciphertext) 
                    continue
        
        return results

    def _is_meaningful(self, text: str) -> bool:
        letters = sum(c.isalpha() for c in text)
        spaces = text.count(' ')
        return len(text) > 0 and letters / len(text) > 0.7 and spaces > 0

 
 