# APSI: C++ library for Private Segmented Membership Test (PSMT)

- [Introduction](#introduction)
  - [Private Membership Test](#(unlabeled)-psi-and-labeled-psi)
  - [Sender and Receiver](#sender-and-receiver)
- [How PSMT Works](#how-apsi-works)
  - [Homomorphic Encryption](#homomorphic-encryption)
  - [Theory](#theory)
  - [Practice](#practice)
- [Using PSMT](#using-apsi)
  - [Receiver](#receiver)
  - [Sender](#sender)
  - [Domain Extension Polynomial (DEP) parameters](#psiparams)
- [Building APSI](#building-apsi)
- [Command-Line Interface (CLI)](#command-line-interface-(cli))
  - [Common Arguments](#common-arguments)
  - [Receiver](#receiver-1)
  - [Sender](#sender-1)
  - [Test Data](#test-data)

## Introduction

### Private Segmented Membership Test (PMT)

Private Segmented Membership Test refers to a functionality where there exist two or more parties known as senders and a single party known as the receiver. Each of the senders hold a private set of *items* and receiver holds a single item. Using PSMT, receiver can check if the single item is present in the privaet set of *items* without revealing anything to the senders.
We use the terminology *sender* and *receiver* to denote the two parties in the PSMT protocol: the senders send the result to the receiver.

## How PSMT Works

### Homomorphic Encryption

PSMT uses a encryption technology known as homomorphic encryption that allows computations to be performed directly on encrypted data.
Results of such computations remain encrypted and can be only decrypted by the owner of the secret key.
There are many homomorphic encryption schemes with different properties; PSMT uses the CKKS encryption scheme implemented in the [OpenFHE](https://github.com/openfheorg) library.

#### Computation on Encrypted Data

OpenFHE enables computation representable with arithmetic circuits (e.g., additions and multiplications modulo a prime number) with limited depths rather than arbitrary computation on encrypted data.
These computations can be done in a *batched* manner, where a single OpenFHE ciphertext encrypts a large vector of values, and computations are done simultaneously and independently on every value in the vector; batching is crucial for PSMT to achieve good performance and high throughput.

#### Noise Budget

The capacity of computation that can be done on encrypted data is tracked by *noise budget* that each ciphertext carries.
A freshly encrypted ciphertext has a certain amount of noise budget which is then consumed by computations &ndash; particularly multiplications.
A ciphertext can no longer be decrypted correctly once its noise budget is fully consumed.
To support computations of larger multiplicative depths, it is necessary to start with a larger initial noise budget, which can be done through appropriate changes to the *encryption parameters*.

#### Encryption Parameters

Choosing the homomorphic encryption schemes parameters is important for obtaining the best performance for the encrypted application, while maintaining the desired level of security. We use 128-bit security level for PSMT and have OpenFHE automatically select the other parameters.
Thus, PSMT does not require the user to explicitly provide the OpenFHE encryption parameters.
We describe some of the important parameters here briefly.

`ringDim` is the ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1).

`poly_modulus_degree` is a positive power-of-two integer that determines how many integers modulo `plain_modulus` can be encoded into a single OpenFHE plaintext; typical values are 2048, 4096, 8192, and 16384.
`poly_modulus_degree` also affects the security level of the encryption scheme: if other parameters remain the same, a bigger `poly_modulus_degree` is more secure.

`firstModSize` and `scalingModSize` are used to calculate ciphertext modulus. The ciphertext modulus should be seen as: Q = q_0 * q_1 * ... * q_n * q':
- q_0 is first prime, and it's number of bits is firstModSize
- q_i have same number of bits and is equal to scalingModSize
- the prime q' is not explicitly given, but it is used internally in CKKS.

`scalingTechnique` is the rescaling switching technique used for CKKS. OpenFHE has techniques such as FLEXIBLEAUTOEXT, FIXEDMANUAL, FLEXIBLEAUTO, etc. for this function.

`batchSize` is the maximum batch size of messages to be packed in encoding (number of slots).

`multiplicativeDepth` is the maximum number of multiplication we can perform before bootstrapping.


### Theory

#### Naive Idea

The basic idea of PSMT is as follows.
Suppose a number of "l" senders holds a set `X` of items &ndash; each a floating point modulo `plain_modulus` &ndash; and the receiver holds a single item `y` &ndash; also a floating point modulo `plain_modulus`. The senders use a public key to encrypt `X` and obtain `c_x`.
The receiver can choose a secret key, encrypts `y` to obtain a ciphertext `c_y = Enc(y)`, and sends it over to the senders.
In case, threshold FHE is used, senders and receiver each obtain a share of the secret key and use the public key to encrypt their sets.

The senders can now evaluate the non-linear *polynomial* `M(c_y, c_x)_i = 1 - tanh^2(c_y - c_x)_i`.
Due to the capabilities of homomorphic encryption, `M(c_y, c_x)_i` will hold an encryption of `1 - tanh^2(c_y - c_x)_i` which is non-zero if `y` matches one of the sender's sets' items and zero otherwise. If threshold FHE is used, senders partially decrypt their results can send them to the receiver for final decryption. The receiver will add all the `M(c_y, c_x)_i` values and if the final result crosses a threshold value that will be the minimum non-zero value mapped by the non-linear polynomial, receiver confirms an intersection, otherwise not.
The senders who performs computation on `c_x` &ndash; encrypted data &ndash; will not be able to know this result due to the secret key being held only by the receiver. In case, threshold FHE is used, senders will not be able to know this result as one of the secret key shares is being held by the receiver.

One problem with the above is that the function `1 - tanh^2(x)` is non-linear can only be computed using linear operations (additions and multiplications) in FHE. One solution is to use the polynomial approximation for computing this function but the computation for such approximation has an enormously high multiplicative depth and requires a very high-degree polynomial for approximation.
It is not common for the senders to have millions items which increases the domain size of the input and eventually the computation needed for approximation.
This would require a very high initial noise budget and subsequently very large encryption parameters with an impossibly large computational overhead.

#### Lowering the Depth

The first step towards making this naive idea practical is to figure out ways of lowering the multiplicative depth of the computation.
First, for the polynomial approximation to work with enough accuracy, we require a high degree polynomial which can handle a large domain interval. We effectively shrink this domain to a smaller interval using [Domain Extension Polynomials (DEP)](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9813691). DEPs enable low-degree polynomial approximation on large intervals. DEPs effectively shrink a large interval `[−𝐿^n 𝑅, 𝐿^n 𝑅]` to a smaller subinterval `[−𝑅, 𝑅]` such that the property of the non-linear polynomial around zero in the smaller subinterval is preserved. The polynomial approximation technique we use after employing DEP is called Chebyshev approximation. `OpenFHE` has a built in method for using Chebyshev approximation. Some guidelines for choosing parameters for polynomial approximation can be found at `https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/FUNCTION_EVALUATION.md`.

The next step is to use batching in OpenFHE.
Per each of the `S` parts described above, the sender can further split its set into `poly_modulus_degree` many equally sized parts, and the receiver can batch-encrypt its item into a single batched query ciphertext `Q = Enc([ X, X, ..., X ])`.
Now, the sender can evaluate vectorized versions of the matching polynomials on `Q`, improving the computational complexity by a factor of `poly_modulus_degree` and significantly reducing the multiplicative depth.


#### False Positives

In some cases the protocol may result in a false positive match.
For example, a bad approximation accuracy of non-linear function can cause the result to contain non-zero values even in cases where `y` does not match one of the sender's sets' items.

There are multiple ways of preventing this from happening. We used a technique involving homomorphic squaring and scaling. First, we squared all the values such that the non-intersection values are mapped to smaller and smaller values (since they are in the interval `[0,1)`). Then, we scale those value using a scaling factor, to increase the difference between values that were meant to be mapped to non-zero and zero values. Now, squaring these values again, would increase the difference further.


## Using SPSI

### Receiver

The `receiver.cpp` file implements all necessary functions to create a receiver and process any responses received.
For simplicity, we use `Receiver` to denote `receiver.cpp`.

`Receiver` includes the functionality to write to the file system its query ciphertext. After the senders compute the polynomial approximations, the receiver reads the result and decrypts it to check if it crosses a pre-determined threshold value. The threshold value is communicated to the receiver during parameter setting.

### Sender(s)

The `sender.cpp` class implements all necessary functions to process and respond to a receiver query.
For simplicity, we use `Sender` to denote `sender.cpp`.
`Sender` batches the query into a single ciphertext and performs the polynomial approximation on the batched ciphertext.

### DEP Params


## Building PSMT

To simply use the PMST library, we recommend to build and install PSMT with [vcpkg](https://github.com/microsoft/vcpkg).
To use the example command-line interface or run tests, follow the guide below to build and [install APSI manually](#building-and-installing-apsi-manually).

### Requirements

| System  | Toolchain                                             |
|---------|-------------------------------------------------------|
| Linux   | Clang++ (>= 7.0) or GNU G++ (>= 7.0), CMake (>= 3.13) |

### Building and Installing PSMT

APSI has multiple external dependencies that must be pre-installed. They are listed in `dependencies.sh`.

## Command-Line Interface (CLI)

The APSI library comes with example command-line programs implementing a sender and a receiver.
In this section we describe how to run these programs.

### Common Arguments

The following optional arguments are common both to the sender and the receiver applications. They help setup the encryption parameters, cryptocontext and keys.

| Parameter | Explanation |
|-----------|-------------|
| `-c` | Cryptocontext file |
| `-p` | Public key file |
| `-r` | Private key file |
| `-e` | Evaluation keys file |
| `-e` | Evaluation keys file |
| `-t` | Scheme (BFV or CKKS) |
| `-s` | A power to include (only for BFV) |
| `-q` | Whether to make (default) or decrypt a query |

### Receiver

The following arguments specify the receiver's behavior.

| Parameter | Explanation |
|-----------|-------------|
| `-q` | Whether to make (default) or decrypt a query |

### Sender

The following arguments specify the sender's behavior and determine the parameters for the protocol.
Note that the receiver may already know the parameters, and the parameter request may not be necessary.

| Parameter | Explanation |
|-----------|-------------|
| `-l` | Low degree for Paterson-Stockmeyer (leave unspecified to use naive dot polynomial evaluation; only for BFV) |
| `-m` | File containing sender inputs |
| `-n` | The number of ciphertexts |
| `-b` | The size of senders' sets in bits |


### Test Data

The library contains a Python script [caoe-cerberus-query/utilities/gen_emails.py](caoe-cerberus-query/utilities/gen_emails.py) that can be used to easily create test data for the CLI.
Running the script is easy; it accepts various optional parameters as follows:

| Flag | Explanation |
|-----------|-------------|
| `EXECUTIVE` | Turn this on for the executive summary only |
| `SETUP` | This sets up the encryption parameters and cryptocontext from scratch |
| `ONLINE` | This turns on the online mode for PSMT |
| `DO_HASHING` | This enables the hashing of the elements to be queried |
| `PARALLEL` | This enables parallel processing wherever possible |
| `ONE_SITE` | Turn this on to make sure only one site has the share of the decryption keys |
| `INTERSECTION` | Use this flag to enable/disable intersection in the sets during query |
| `TYPE` | This can be set to the encryption scheme to be used (BFV or CKKS) |
| `NUM_PARTIES` | Use this to set the number of parties that are involed in the protocol |
| `NUM_KEY_SHARES` | Use this to set up the number of parties who can hold the secret key share |


```
INTERSECTION=1 EXECUTIVE=1 DO_HASHING=0 TYPE=CKKS ONE_SITE=1 ./demo_aug31.sh
```


## Acknowledgments


## Contributing
For contributing to APSI, please see [CONTRIBUTING.md](CONTRIBUTING.md).
