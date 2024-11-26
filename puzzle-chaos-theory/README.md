# puzzle-chaos-theory

**DO NOT FORK THE REPOSITORY, AS IT WILL MAKE YOUR SOLUTION PUBLIC. INSTEAD, CLONE IT AND ADD A NEW REMOTE TO A PRIVATE REPOSITORY, OR SUBMIT A GIST**

Trying it out
=============

Use `cargo run --release` to see it in action

Submitting a solution
=====================

[Submit a solution](https://xng1lsio92y.typeform.com/to/UYMwUsgG)

[Submit a write-up](https://xng1lsio92y.typeform.com/to/NGwTHlVz)

Puzzle description
==================

    |___  /| | / / | | | |          | |
       / / | |/ /  | |_| | __ _  ___| | __
      / /  |    \  |  _  |/ _` |/ __| |/ /
    ./ /___| |\  \ | | | | (_| | (__|   <
    \_____/\_| \_/ \_| |_/\__,_|\___|_|\_\

Bob designed a new one time scheme, that's based on the tried and true method of encrypt + sign. He combined ElGamal encryption with BLS signatures in a clever way, such that you use pairings to verify the encrypted message was not tampered with. Alice, then, figured out a way to reveal the plaintexts...

Code exploring
==================
We start with some notations

$r_s$: private key of sender, $r_s[G_1]$: public key of sender.

$r_r$: private key of receiver, $r_r[G_1]$: public key of receiver.

$h()$: hash function, which return an element in group $G_2$.

$M$: message (as field element)

Source code consists of only 1 file, `main.rs`.

`ElGamal` declaration include 2 elements in group $G_1$. The `hash_to_curve` function return a hash in group $G_2$.
```rust
pub struct ElGamal(G1Affine, G1Affine);

impl ElGamal {
    pub fn hash_to_curve(&self) -> G2Affine {
        let mut data = Vec::new();
        self.serialize_uncompressed(&mut data).unwrap();

        hasher().hash(&data).unwrap()
    }
}
```

`Sender`'s method is not called directly in the `main` function, but it is what generated blob in `blob.bin` file.

`send()` create ElGamal encryption which includes sender's public key, $c_1=r_s[G_1]$ and $c_2=(r_sr_r+m)[G_1]$, $c$ is kind of concatenated of $c=c_1||c_2$.

`authenticate()` create a signature $s=r_sh(c)[G_2]$.

```rust
impl Sender {
    pub fn send(&self, m: Message, r: &Receiver) -> ElGamal {
        let c_2: G1Affine = (r.pk.mul(&self.sk) + m.0).into_affine();
        ElGamal(self.pk, c_2)
    }

    pub fn authenticate(&self, c: &ElGamal) -> G2Affine {
        let hash_c = c.hash_to_curve();
        hash_c.mul(&self.sk).into_affine()
    }
}
```
The `Auditor check_auth()` does the check that whether data received by received is valid
```rust
impl Auditor {
    pub fn check_auth(sender_pk: G1Affine, c: &ElGamal, s: G2Affine) -> bool {
        let lhs = { Bls12_381::pairing(G1Projective::generator(), s) };

        let hash_c = c.hash_to_curve();
        let rhs = { Bls12_381::pairing(sender_pk, hash_c) };

        lhs == rhs
    }
}
```
The `generate_message_space()` function return a space of message, consist of 10 points on $G_1$. Our objective is to decipher which one is the message sent by sender.
```rust
fn generate_message_space() -> [Message; 10] {
    let g1 = G1Projective::generator();
    let msgs = [
        390183091831u64,
        4987238947234982,
        84327489279482,
        8492374892742,
        5894274824234,
        4982748927426,
        48248927348927427,
        489274982749828,
        99084321987189371,
        8427489729843712893,
    ];
    msgs.iter()
        .map(|&msg_i| Message(g1.mul(Fr::from(msg_i)).into_affine()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

```
Analyzing
==================

The receiver got: public key of sender, its own key pair, the encrypted message $r_sr_r+m[G_1]$

In our own situation, we (the attacker) have same information as receiver side EXCEPT receiver private key $r_r$. Only public keys: $r_s[G_1], r_r[G_1]$

Hmm, we have $r_s[G_1]$, $r_r[G_1]$, $r_sr_r[G_1]$. Seems we can utilize these for bilinear pairing equation.

Let's start with a trivial pairing equation we can think of: $e(r_sr_r,1) = e(r_r,r_s)$. Here, we ignore the group of each elements.

We need to cancel $m$ in $c_2$ to get the product of $r_s$ and $r_r$. Need to check $e(c_2-m_i,1)=e(r_sr_r+m-m_i,1) \stackrel{?}{=}  e(r_sr_r,1) = e(r_r,r_s)$ for every message $m_i$ in message space?

Equation happens iff $m=m_i$. A notice here $m$ is a field element, not a raw message, if we considered raw message, the relation is not iff because of hash collision)

If $m = m_i$, $e(c_2-m_i,1) = e(r_sr_r,1) = e(r_r,r_s)$

Notice that we ignored group in above statements. Because both public key are in group $G_1$, we can't do bilinear pairing $e(r_r,r_s)$ here.

But look at an existing bilinear pairing in souce code, we already have $r_sh(c)[G_2]$. Now we can put which group in the checking statement:

$e(c_2-m_i[G_1],h(c)[G_2])=e(r_sr_r+m-m_i[G_1],h(c)[G_2]) \stackrel{?}{=} e(r_sr_r[G_1],h(c)[G_2]) = e(r_r[G_1],r_sh(c)[G_2])$

$r_sh(c)$ is the signature we received. Equation happens iff $m=m_i$

With this, we can basically try every message in message space to find when the equation happen.

Implementation
==================
Just one main line to get the index thanks to iter of rust.
```rust
    let Blob {sender_pk: _, c , s, rec_pk: receiver_pk} = blob;
    let index = messages.iter()
        .enumerate()
        .filter(|(_, &Message(m))| Bls12_381::pairing(receiver_pk, s) == Bls12_381::pairing(c.1 + m.neg(), c.hash_to_curve()))
        .map(|(i, _)| i)
        .collect::<Vec<_>>()[0];
  
    println!("Index of the encrypted message {:?}", index);

```
To use `neg()`, we need to import Neg.
```rust
use std::ops::Neg;
```