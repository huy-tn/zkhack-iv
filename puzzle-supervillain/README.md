# puzzle-supervillain

Trying it out
=============

Use `cargo run --release` to see it in action

Puzzle description
==================

    |___  /| | / / | | | |          | |
       / / | |/ /  | |_| | __ _  ___| | __
      / /  |    \  |  _  |/ _` |/ __| |/ /
    ./ /___| |\  \ | | | | (_| | (__|   <
    \_____/\_| \_/ \_| |_/\__,_|\___|_|\_\

Bob has been designing a new optimized signature scheme for his L1 based on BLS signatures. Specifically, he wanted to be able to use the most efficient form of BLS signature aggregation, where you just add the signatures together rather than having to delinearize them. In order to do that, he designed a proof-of-possession scheme based on the B-KEA assumption he found in the the Sapling security analysis paper by Mary Maller [1]. Based the reasoning in the Power of Proofs-of-Possession paper [2], he concluded that his scheme would be secure. After he deployed the protocol, he found it was attacked and there was a malicious block entered the system, fooling all the light nodes...




BLS signature scheme and Rogue key Attack
=====================
>The magic behind FBFT consensus is the Boneh–Lynn–Shacha (BLS) signature algorithm. Under this signature scheme, multiple validators sign a common message (i.e. the current block), their public keys (i.e. validator’s BLS public key) can be aggregated (or added ) together to form a new public key and the resulting signatures (from each validator) can also be aggregated together to form a new signature. Instead of verifying each individual validator’s signature with its corresponding public key, we (or other validators) only need to verify the aggregated signature against the aggregated public key.


>Rogue public key attack against Harmony consensus can be achieved with a malicious leader. Suppose we have N-1 validators and 1 leader with public key P1, P2, P3…PN for consensus. The leader broadcast blockX to all the validators and validators sign blockX with their keys and send back their signatures S1,S2,S3…SN to the leader. The leader then broadcasts the aggregated signature S=S1+S2+…+SN to all the validators. The consensus is reached when the validators validate S with P=P1+P2 +…+PN. Please note that I used a simplified version of the FBFT consensus protocol in my description, the actual FBFT includes more things like Quorum, etc. But what if the current leader is malicious and wants to modify the content of blockX (e.g. double-spend etc). The leader can generate a new key pair P’ and sign blockXmod with the new key and get new signature S’. To make the signature aggregation work, the leader needs to replace the original PN with a rouge public key PN’, where PN’ =P’- P1-P2-…PN-1 and replace original aggregated signature SN with SN’ =S’ -S1-S2-…-SN-1 . All the other validators then do key aggregation and get P’ = P1+P2 +…+PN’ and S’ = S1+S2+…+SN’ as the aggregated public key and signature. The validators will validate the signature and consensus is reached with blockXMod!
[3]

To defense against Rogue key Attack, Bob introduced a POK mechanism implemented by his own.

Notation
=====================
We (the malicious leader) receive POP/POK (Proofs-of-Possession/Proofs-of-Knowledge) from validators, numbered from $1$ to $N-1$. Each validator send public key and the proof. The subscript $N$ is for us.
- Private key: $r_i$
- Group element, can be a public key in $G_1$, or a signature or proof in $G_2$: $x[G_i], i\in\{1,2\}$
- Public key: $p_i = r_i[G_1]$
- Aggregate private key: $r = \sum\limits_{i=1}^{N}r_i$
- Proof for POK: $\pi_i$, will find out what is it later
- Since we are malicious, our proof and keys are notated with prime $\pi'_N$, $r'_N$, $p'_N$.
- Also, the aggregated ones are: $\pi' = \pi'_N + \sum\limits_{i=1}^{N-1}\pi_i$, $r' = r'_N + \sum\limits_{i=1}^{N-1}r_i$, $p' = p'_N + \sum\limits_{i=1}^{N-1}p_i$

Explore source code
=====================
Source code is only one `main.rs` file.

In `main` function, we read a bin file contains public key and proof (for POK) from all validators. Each validator created the proof by signing on a point on $G_2$.
```rust
    let public_keys: Vec<(G1Affine, G2Affine)> = from_file("public_keys.bin");
```
If we were a good leader, we would use our key to sign the message for BLS verification, and sign a dedicated point on G2 to create a proof for POK verification. Then, aggregate our public key and signature with those of validators. The puzzle omitted signatures from validators.

Both BLS verification and POK verification are group pairing test: $e(r[G_1], -H[G_2]) + e(1[G_1], rH[G_2]) = 0$
- In BLS verification, $H=hash(m)$ is hash of the message, $rH$ is the signature (multiply the hash with private key).
- In POK verification, validator can be seen as prover, $rH$ is the proof and $H$ is the pre-image (also a point on $G_2$).

```rust
  fn pok_verify(pk: G1Affine, i: usize, proof: G2Affine) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[derive_point_for_pok(i).neg(), proof]
    )
    .is_zero());
  }

  fn bls_verify(pk: G1Affine, sig: G2Affine, msg: &[u8]) {
      assert!(Bls12_381::multi_pairing(
          &[pk, G1Affine::generator()],
          &[hasher().hash(msg).unwrap().neg(), sig]
      )
      .is_zero());
  }
```
We need to create a public key, a proof, a signature to bypass the test, which mean that we successfully modified the block (message) into our own dictated version (the GitHub username), which means passing tests without panicking.
```rust
  pok_verify(new_key, new_key_index, new_proof);
  let aggregate_key = public_keys
      .iter()
      .fold(G1Projective::from(new_key), |acc, (pk, _)| acc + pk)
      .into_affine();
  bls_verify(aggregate_key, aggregate_signature, message)
```

Source code provided us some utility functions without anything special inside: 
- `hasher`: hash function to hash a message of type string (more exactly, the hash function is `hasher().hash()`).
- `from_file`: read public key and proof from a prepared bin file.
- `bls_sign`: sign a message with a private key.

Forge
=====================

To pass the BLS verify, we need to sign the modified message (which is the GitHub username) with our aggregated private key. This mean this key should be known.

To make this happen, all unknown terms must be neutralized $r_i (0 < i \leq N-1)$ and $r'_N$ in the aggregated private key $r'$.

Let's use a key that negate all validators' key : $r'_N = r^* - \sum\limits_{i=1}^{N-1}r_i$ with a known $r^*$. This make $r' = r^*$.

Aggregated public key is computable based on those of validators:
$p'_N = r'_N[G_1] = (r^* - \sum\limits_{i=1}^{N-1}r_i)[G_1] = r^*[G_1] - \sum\limits_{i=1}^{N-1}p_i$

Now we need to take care about the POK proof.

By observe `derive_point_for_pok` function (used by `pok_verify` and `pok_proof`), we can see the message, and of course, the proof are rational with validator index: $\pi_i = r_ici[G_2]$. Here $c[G_2]$ is `G2Affine::rand(rng)`, a constant because `rng` is initialized each time `derive_point_for_pok` is called. This suggests that when having this proof, we can "replace" validator index with our own, which is $N$.
```rust
fn derive_point_for_pok(i: usize) -> G2Affine {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(20399u64);
    G2Affine::rand(rng).mul(Fr::from(i as u64 + 1)).into()
}

fn pok_prove(sk: Fr, i: usize) -> G2Affine {
    derive_point_for_pok(i).mul(sk).into()
}
```
For POK verification, we can't create $\pi'_N$ using this definition directly since we don't know $r'_N$. 

But based on the above characteristic, the proof can be forged:

$$
\begin{align*}
\pi'_N = r'_NcN[G_2] &= (r^* - \sum\limits_{i=1}^{N-1}r_i)cN[G_2] \\
&= r^*cN[G_2] - N\sum\limits_{i=1}^{N-1}r_ic[G_2] \\
&= r^*cN[G_2] - N\sum\limits_{i=1}^{N-1}\frac{\pi_i}{i}[G_2] \\
\end{align*}
$$

The minuend is the proof with private key $r^*$, and the subtrahend is a linear combination of $\pi_0, \pi_1, ... , \pi_{N-1}$ with known (computable) weights.
Yeah, we can compute $\pi'_N$ without knowing $r'_N$. Shame on Bob's POK!


Implementation
=====================
```rust
    let private_key = Fr::from(123); //rstar, arbitrary element from Fr
    let aggregate_signature = bls_sign(private_key, message); //sign by rstar like normal message
    let known_proof = pok_prove(private_key, new_key_index); //proof's minuend

    let forge_public_key = G1Affine::generator().mul(private_key); 
    let aggregate_key_validators = public_keys
        .iter()
        .fold(G1Projective::zero(), |acc, (pk, _)| acc + pk);

    let new_key = (forge_public_key + aggregate_key_validators.neg()).into_affine(); 

    let aggregate_proof_validators = public_keys
        .iter()
        .enumerate()
        .fold(G2Projective::zero(), |acc, (i, (_, proof))| acc + proof.mul(Fr::from(i as u64 + 1).inverse().unwrap())); //proof's subtrahend

    let new_proof = (known_proof + aggregate_proof_validators.mul(Fr::from(new_key_index as u64 + 1)).neg()).into_affine(); 
```

We need to import Field to use `inverse()`
```rust
use ark_ff::Field;
```
In comparison with the submitted code, I removed `to_affine()` for intermediate values, changed some variable names and added some comments.

Notes
=====================

I've done this puzzle without understanding very deeply about how a POK is implemented, so I don't know what's the different between Bob's approach and that of Sapling. I end this write-up here without proposing a method to fix it.

References
=====================
- [1] https://github.com/zcash/sapling-security-analysis/blob/master/MaryMallerUpdated.pdf
- [2] https://rist.tech.cornell.edu/papers/pkreg.pdf
- [3] https://medium.com/@coolcottontail/rogue-key-attack-in-bls-signature-and-harmony-security-eac1ea2370ee