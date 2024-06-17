# A VOPRF Implementation for Fastly Edge Compute

This is a very simple [VOPRF](https://datatracker.ietf.org/doc/html/rfc9497)
that uses the [Ristretto255 group](https://datatracker.ietf.org/doc/html/rfc9497#name-oprfristretto255-sha-512).

It uses Fastly's edge compute secret store.

## Client

A basic client is included.  That client takes the URL of the server as a single
argument.

The client reads an input from stdin, contacts the server to obtain a public
key and VOPRF result, validates that result, then emits the resulting value to
stdout.
