# Keybeat

Keybeat is a very simple CLI built in Python that creates and validates proofs of life. I originally built this for a *dead man's switch* system, which is designed to allow access to files and the like in the event of a person's death, but that requires a way to prove that a person is still alive. Such a system is subject to two kinds of attacks: someone trying to create proofs in advance, and someone trying to invalidate existing proofs. By using cryptographic signatures through GPG, the latter problem is mitigated, and the former can be prevented by using a time challenge --- this is a simple idea whereby some server issues, say, a random number every hour, and this acts much like the headline on a newspaper: if you sign that, everyone else knows for sure you made that signature at earliest when the random number was published, on a specific hour.

Of course, any central server may be subject to all sorts of intervention, and, although the NIST randomness beacon seems like a pretty good source for most applications, a dead man's switch needs to be resistant to attacks from state-level actors in some cases (which NIST, controlled by the US government, is likely not), so Keybeat uses a decentralised source of randomness: the hash of the latest block on the Bitcoin blockchain. As so many people contribute to this source of randomness, and as there are already clear economic incentives to do so, only a person in control of 51% of the hashing power of the network would be able to reliably interfere with what that hash ends up being or predict it in advance, and, for a daily proof of life challenge, it is effectively impossible to predict the hash of the block released around 9:00 in the morning a day in advance!

## Usage

You can install Keybeat like so:

``` sh
pip install keybeat
```

From here, there are three simple commands: `keybeat create`, which makes a new proof-of-life; `keybeat validate <proof-string> -a <max-age-seconds> [-p <public-key-file>]`, which cryptographically validates the given proof (give `-` to read it from stdin) and makes sure it is no older than the given number of seconds; and `keybeat get-time <proof-string> [-p <public-key-file>]`, which gets the time at which a proof was created.

Keybeat is backed by GPG, so you should make sure that a command like `echo test | gpg --sign | gpg --verify` works and tells you *"Good signature"*. If not, you may need to install GPG and create a private key, for which there are endless guides online.

## License

See [`LICENSE`](LICENSE).
