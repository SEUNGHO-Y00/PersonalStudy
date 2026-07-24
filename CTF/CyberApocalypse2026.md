# Cyber Apocalypse 2026

## Crypto

### Lamport-style one-time signature

* [Lamport one-time signature scheme](https://www.youtube.com/watch?v=SSfom9U5ugk&t=11s)
* A Lamport signature is a quantum-resistant digital signature scheme created by Leslie Lamport.
* How the Keys Work
  - Secret Key: You pick random secret data. For every bit in your message, you pick two secret random numbers (x₀ and x₁).
  - Public Key: You hash all your secret numbers to make your public key (y₀ and y₁).
  - Size: Both keys and the signature are very large because you need a pair of numbers for every single bit of the data you sign.
 
* Preimage resistance is a core security property of cryptographic hash functions. It ensures that given a specific hash output, it is computationally infeasible to determine the original input data. This "one-way" nature prevents attackers from reversing the math to uncover plaintext messages, passwords, or encrypted files.

* Code
```python
def keygen():
    sk = [(secrets.randbelow(2**N), secrets.randbelow(2**N)) for _ in range(N)]
    pk = [(H(s[0]), H(s[1])) for s in sk]
    return sk, pk
```

### multivariate-cryptography (HFE)

* Multivariate cryptography is a form of post-quantum cryptography based on the difficulty of solving systems of non-linear polynomial equations over finite fields.
* Hidden Field Equations (HFE) is one of its most famous variations, proposed by Jacques Patarin in 1996 to build public-key encryption and digital signature systems.

### RSA partial-key-exposure / Coppersmith attack

* Coppersmith's attack is a powerful cryptographic method used to find small roots of modular polynomial equations, making it a major threat to RSA encryption when public exponents are small or when parts of the secret message are known.
