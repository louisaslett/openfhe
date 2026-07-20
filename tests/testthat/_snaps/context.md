# context printing is informative

    Code
      show(toy("CKKS"))
    Output
      <OpenFHE CKKS context>
        ring dimension 1024 (512 slots) | mult depth 2 | security: none (toy parameters, NOT secure)
        features: PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE

---

    Code
      show(toy("BFV"))
    Output
      <OpenFHE BFV context>
        ring dimension 1024 (1024 slots) | mult depth 2 | security: none (toy parameters, NOT secure)
        features: PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE

