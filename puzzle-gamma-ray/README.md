# Problem
Bob was deeply inspired by the Zcash design for private transactions and had some pretty cool ideas on how to adapt it for his requirements. He was also inspired by the Mina design for the lightest blockchain and wanted to combine the two. In order to achieve that, Bob used the MNT6753 cycle of curves to enable efficient infinite recursion, and used elliptic curve public keys to authorize spends. He released a first version of the system to the world and Alice soon announced she was able to double spend by creating two different nullifiers for the same key... 

# What we don't need to understand (for solving this puzzle)
In this write-up, I use the term private key and secret interchangably, since private (rather than secret) seems more opposed with public.

About 2 MNT curves, since we only work with one curve (but with one?) we don't need to care about the relationship, just treat them as 2 different curves, except the fact

> Ark documentation: The main feature of this curve is that its scalar field and base field respectively equal the base field and scalar field of MNT6_753: $r_6 = q_4, r_4 = q_6$

We don't need to research about Mina for this problem. Basically, Bob use Groth with MNT curve, which is the only thing to address Mina here. 

Don't need to deep dive about Groth16 neither.

# Explore
The poseidon_parameteres.rs is just configuration for the Poseidon hash function. We don't need to touch it
Bin files are inputs for the circuit and proof.
The main focus should be main.rs, which contains main function and the ConstraintSynthesizer, along with some other declarations.
- ConstraintSynthesizer is for creating circuit. Understanding that we need to provide a good witness (a secret and a nullifier) to create a proof is enough.
Based on the hints and some discussion on Discord.
- main function is the entrypoint of this puzzle, which is basically do what we usually do with a proving system. In this case, it is proving that we know a Merkle proof for a secret and this secret hasn't been spent (nullifier is not in spent set).

Yeah, I think about some directions:
- Using hash collision attack based on the Pedersen hash. However, Bob uses Poseidon hash instead of Pedersen, and after a while research about this, I believe that it can't be attacked with the similar the trick used with the Pedersen.
- Also, finding another hash that can be a leaf in the root is not possible. The hash should be unchanged and we need to forge a secret that create identical pre-image, which will return identical hash (hash collision).
- Based on the hints, and explore the code, we can see that the ConstraintSynthesizer using only the x component for the public key (point on MNT curve). Moreover, the MNT curve is used as Weierstrass form, this allow us to find the $pk' = -pk$
```rust
        let base = G1Var::new_constant(ark_relations::ns!(cs, "base"), G1Affine::generator())?;
        let pk = base.scalar_mul_le(secret_bits.iter())?.to_affine()?;

        // Allocate Leaf
        let leaf_g: Vec<_> = vec![pk.x];
```
- For nullifier, with Zcash implementation, it is a function of the secret, so if we had the secret_hack, it will be generated with the similar function with 
```rust

        let nullifier_hack = <LeafH as CRHScheme>::evaluate(&leaf_crh_params, vec![secret_hack]).unwrap();
```
# Pwn
My first try is simply negate the leaked_secret (private key)
```rust
        let secret_hack = -leaked_secret;
```
Failed!

Of course, negate the private key is true, but this is finite field. More important, which finite field?
I think Bob worked with MNT4753 curve because of the wrapper in main
```rust
        let leaked_secret: MNT4BigFr = from_file("./leaked_secret.bin");
```
but when I re-scan the generate_constraints, I found declration of generator point. It belongs to MNT6753:
```rust
        use ark_mnt6_753::G1Affine;
        use ark_mnt6_753::{constraints::G1Var, Fr as MNT6BigFr};

        Boolean::enforce_smaller_or_equal_than_le(&secret_bits, MNT6BigFr::MODULUS)?;
```
Yes, the curve used in public key generation is consistent with the enforce statement. We can conclude that Bob use MNT6753 curve for pairing (actually this is written in the original statement above). Now, we need to negate the secret on the $\mathbb{F}_{r6}$ field. Though in the main function, Bob use MNT4Fr ($\mathbb{F}_{r6}$) to wrap the secret, but it's just a wrapper around an integer. It's not very different if we just wrap a number and don't do any operation on it (of course it's still different because of modulo, should happen when $q_4 = r_6 < secret < r_4$, smaller here is for modulo-ed secret integer).
```rust
        let zero_q = MNT4BigFr::from(MNT6BigFr::MODULUS); //MNT6BigFr::MODULUS = MNT4BigFq::MODULUS
        let secret_hack = zero_q - leaked_secret;
        let nullifier_hack = <LeafH as CRHScheme>::evaluate(&leaf_crh_params, vec![secret_hack]).unwrap();
```
In $\mathbb{F}_{r6}$: $-leaked\_secret = r_6 - leaked\_secret$. My code is a little confused, since I still use MNT4BigFr as wrapper, but it works with the provided secret (so, I decided to stop and start working with this write up). In some edgy cases (eg: $r_6 < secret < r_4$), it will fail!
An improved pseudo-code should be:
```rust
        secret = leaked_secret as of using in mutiplication with Generator
        let secret_hack = negate of MNT6BigFr::from(secret)
```
with secret here equal leaked_secret_as_integer modulo $\mathbb{F}_{r6}$. In general case, we even can't read leaked_secret hack from bin file, since the circuit worked with the wrapped version to hash and generate proof
I haven't tried with other secret values,
# How to prevent
In the Zcash protocol, the team use Jubjub curve with a subgroup that satisfied lemma 5.4.7, which mean two negate value should not belong to same subgroup. In Bob's case, this can be fixed by use both coordinates instead of just use $pk.x$.
# Some thoughts
Before have the solution by negating secret with the right field, I am stuck at some unrelevant:
- The little endian vs big endian
- The conversion between Affine form and Projective form. I am not very clear about this. but with the above code, the G1Affine::generator() contains 2 number coordinates (x, y), but the base we got with new_constant contains 3 coordinates (name x, y, z). I guess this is a projective generator. I think the conversion to Projective form is mainly for optimize the number of constraints.

Both endian and curve form stuff are not directly affect the private key (secret), but they make me confusing about do we need another way to create negate of private key. No, they don't!
- Learned a lot about arkworks through this puzzle.
- ChatGPT (MS Copilot) helped me a lot especially when answering questions about cryptographic and elliptic curve. But it's not very helpful when generating code in comparison with more popular languages like Python, JavaScript...
- A remaining question is MNT4_753 template in Groth16 declaration. Why not MNT6_753?
```rust
        Groth16::<MNT4_753>
```
# References

- https://en.bitcoin.it/wiki/Secp256k1
- https://research.nccgroup.com/2023/03/22/breaking-pedersen-hashes-in-practice/
- https://www.youtube.com/watch?v=TlfGs7ExC0A&t=279s
- https://en.wikipedia.org/wiki/Twisted_Edwards_curve
- https://medium.com/@prajwolgyawali/getting-started-with-arkworks-rs-e5ceaca895a9
- https://docs.rs/crate/ark-mnt4-753/0.4.0