import re
from collections import Counter

def clean_text(text):
    """Remove non-letters and convert to lowercase."""
    return ''.join([c.lower() for c in text if c.isalpha()])

def find_repeated_patterns(text, length):
    """Find repeated patterns of given length in the text."""
    patterns = {}
    for i in range(len(text) - length + 1):
        pattern = text[i:i + length]
        if pattern in patterns:
            patterns[pattern].append(i)
        else:
            patterns[pattern] = [i]
    return {k: v for k, v in patterns.items() if len(v) > 1}

def gcd(a, b):
    """Compute the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def find_key_length(text, max_key_length=20):
    """Estimate key length by finding repeated patterns and calculating distances."""
    cleaned_text = clean_text(text)
    distances = []
    for length in range(3, max_key_length + 1):
        patterns = find_repeated_patterns(cleaned_text, length)
        for indices in patterns.values():
            for i in range(len(indices) - 1):
                distances.append(indices[i + 1] - indices[i])
    if distances:
        common_factors = Counter(gcd(distance, max_key_length) for distance in distances)
        likely_key_length = common_factors.most_common(1)[0][0]
        return likely_key_length
    return None

def frequency_analysis(text):
    """Perform frequency analysis on the text."""
    frequency = Counter(text)
    total = len(text)
    return {char: count / total for char, count in frequency.items()}

def shift_decrypt(text, shift):
    """Decrypt text with a given shift (Caesar cipher)."""
    return ''.join(chr((ord(char) - shift - ord('a')) % 26 + ord('a')) for char in text)

def chi_squared_statistic(text, shift):
    """Calculate the chi-squared statistic for a given shift."""
    expected_freqs = {
        'a': 0.082, 'b': 0.015, 'c': 0.028, 'd': 0.043, 'e': 0.13,
        'f': 0.022, 'g': 0.02, 'h': 0.061, 'i': 0.07, 'j': 0.0015,
        'k': 0.0077, 'l': 0.04, 'm': 0.024, 'n': 0.067, 'o': 0.075,
        'p': 0.019, 'q': 0.00095, 'r': 0.06, 's': 0.063, 't': 0.091,
        'u': 0.028, 'v': 0.0098, 'w': 0.024, 'x': 0.0015, 'y': 0.02, 'z': 0.00074
    }
    
    decrypted_text = shift_decrypt(text, shift)
    observed_freqs = frequency_analysis(decrypted_text)
    
    chi_squared = 0
    for char in expected_freqs:
        observed = observed_freqs.get(char, 0) * len(decrypted_text)
        expected = expected_freqs[char] * len(decrypted_text)
        chi_squared += (observed - expected) ** 2 / expected
    
    return chi_squared

def crack_caesar(ciphertext):
    """Crack Caesar cipher using chi-squared statistic."""
    chi_squared_values = []
    for shift in range(26):
        chi_squared = chi_squared_statistic(ciphertext, shift)
        chi_squared_values.append((shift, chi_squared))
    
    best_shift = min(chi_squared_values, key=lambda x: x[1])[0]
    return best_shift

def split_text_by_key_length(text, key_length):
    """Split text into segments based on the key length."""
    segments = ['' for _ in range(key_length)]
    for i, char in enumerate(text):
        segments[i % key_length] += char
    return segments

def crack_vigenere(ciphertext, key_length):
    """Crack Vigenère cipher given the key length."""
    segments = split_text_by_key_length(clean_text(ciphertext), key_length)
    key = ''
    for segment in segments:
        shift = crack_caesar(segment)
        key += chr(shift + ord('a'))
    return key

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenère cipher with a given key."""
    key_indices = [ord(k) - ord('a') for k in key]
    key_length = len(key)
    cleaned_text = clean_text(ciphertext)
    plaintext = ''
    for i, char in enumerate(cleaned_text):
        shift = key_indices[i % key_length]
        decrypted_char = chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
        plaintext += decrypted_char
    return plaintext

def main():
    try:
        with open('ciphertext.txt', 'r') as file:
            ciphertext = file.read().replace('\n', '').replace(' ', '')
            
        likely_key_length = find_key_length(ciphertext)
        if likely_key_length:
            print(f"Likely key length: {likely_key_length}\n")
            key = crack_vigenere(ciphertext, likely_key_length)
            print(f"Cracked key: {key}\n")
            plaintext = vigenere_decrypt(ciphertext, key)
            print("Decrypted plaintext: \n")
            print(plaintext)
        else:
            print("Could not determine the key length.")
    except FileNotFoundError:
        print("ciphertext.txt file not found. Please make sure the file exists in the same directory as this script.")

if __name__ == "__main__":
    main()