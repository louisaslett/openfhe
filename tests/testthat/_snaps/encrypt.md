# ciphertext printing is informative

    Code
      show(encrypt(c(1.5, 2.5, 3.5), keys))
    Output
      <Encrypted vector[3]> CKKS | level 0 of 2

---

    Code
      show(encrypt(numeric(1000), keys))
    Output
      <Encrypted vector[1000]> CKKS | 2 ciphertexts (512 slots) | level 0 of 2

