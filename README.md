## One time signatures, using Lamport Signature Scheme

Warning: This is not yet for actual use.

This is an implementation of a one-time signature scheme using Lamport
signatures.

Lamport signatures can only be used to sign a single message. To sign multiple
messages with the same key, Merkle trees can be used.

TODO:

    - error handling

    - wiping memory after generating/using keys

    - take message input from a file
