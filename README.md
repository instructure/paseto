# Paseto Rust #

[![Build Status](https://dev.azure.com/instructure-github/github-integration/_apis/build/status/instructure.paseto?branchName=master)](https://dev.azure.com/instructure-github/github-integration/_build/latest?definitionId=1&branchName=master)

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards][blog_post].
This is directly adapted from the reference implemenation made by paragon-ie, which can be found: [HERE][reference_impl].

_NOTE: The license of the original paseto implementation is ISC which is functionally equivelant to MIT, but located: [HERE][reference_license]_

## What is Paseto? ##

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation for secure stateless tokens. You
can find a lot of info about the motivation + benifits of using paseto inside the original paseto repo: [HERE][reference_impl].

## Usage ##

Simply add this crate to your `Cargo.toml` file:

```toml
[dependencies]
paseto = "^1.0.3"
```

and then in your crate root:

```rust
extern crate paseto;
```

## Examples ##

The `examples/` directory covers the following use cases:
  1. Using the protocol directly to encode potentially non-json data.
  2. Using the public builder interface to build a JWT esque equivelant json payload with shared key encryption.
  3. Using the public buidler interface to build a JWT esque equivelant json payload with public key signing.

[reference_impl]: https://github.com/paragonie/paseto
[reference_license]: https://github.com/paragonie/paseto/blob/master/LICENSE
[blog_post]: https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid
