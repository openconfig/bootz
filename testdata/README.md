# Testdata

This directory contains cryptographic artifacts necessary for the Bootz implementation. The files here are included as examples only and real implementations would need their own method of generating, storing and retrieving these.

## ca.pem

This is an x509 certificate that represents the device manufacturer's root (or some intermediate) CA. It is required that the ownership voucher passed from the Bootz server is signed by this CA.