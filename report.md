---
title:      'Industrial Key Infrastructure (IKI)'
---

# Introduction

This research report identifies a set of requirements, technologies, and practices for securing industrial infrastructure
using digital certificates.  This work was originally scoped to apply only to the [SSP21](https://ssp21.github.io), which
specified a custom certificate format designed for easier implementation than the ubiquitous X.509v3 (hereafter x509) format.
After careful consideration and numerous discussions with stakeholders, it is now recommended that SSP21 make primary usage
of X.509 and the related family of technologies.

The original decision to specify an alternative format to X.509 was primarily driven by the complexity of the format. X.509
and its extension contain an abundance of information not relevant to many control, and the format is encoded using ASN.1
DER which is rather complex compared to alternatives.  All of these challenges with X.509 remain true, however, the benefits
now seem to outweigh the issues, namely:

* Using X.509 makes SSP21 less controversial and increases its chances of adoption
* Any extensions specified for usage in X.509 could also be applied to Transport Layer Security (TLS).
* X.509 already has an ecosystem of tools that can either be directly reused or adapted to purpose.

# Requirements: Uniqueness of ICS

Applying security to Industrial Control Systems (ICS) differs from the global internet in important ways. The most
important requirement for applying security is that it cannot adversely impact the availability of the system that it
protects.  We take for granted in IT security that confidentiality and integrity are paramount, and that availability
should be sacrificed in order to protect the others.  In ICS, availability is everything and confidentiality is often
of little importance. The normal CIA triad that implies an ordering of importance is reversed to AIC. Adding security
cannot risk the availability of operations.

## Network Limitations

Many ICS networks, particularly SCADA systems, operate on limited networks.  They may be limited in ways that differ
from the global internet:

* They may use non-routable communications such as modem, serial, and radio.  These links can only carry dedicated
ICS communications.

* The devices have a much longer service lifetime than those used in other industries.

* They links may be highly bandwidth constrained

## Time Synchronization

X.509 constrains the validity of the certificate using the *notBefore* and *notAfter* fields, each of which specifies
a UTC timestamp.  When issuing these certificates, certificate authorities (CAs) use the fields to define the lifetime
of the certificate, explicitly relying on the availability of UTC time synchronization for verifying them.  This
reliance can be problematic as it introduces additional attack surface, namely:

* A denial of service (DoS) on the time synchronization mechanism can now disrupt communications. Introducing the usage
of certificates can ironically make the system much more vulnerable to disruption.

* If time synchronization can be manipulated, the lifetime of certificates can be improperly manipulated.

It is not uncommon for ICS networks to use some form of time synchronization, but it is usually not critical to
maintaining operations or the monitoring of such operations.  For example, electric power systems frequently use one
of the [IRIG](http://irig.org/) standards to synchronize time on protective relays to UTC with sub-cycle precision.
In the event of an outage, this synchronization allows event logs from multiple relays to be correlated for root cause
analysis.  It is a nice-to-have feature for performing a post-mortem analysis, but it is not critical for maintaining
operations.  Requiring UTC time synchronization just to communicate with the relay makes the system more fragile.

In less precision sensitive applications, time synchronization features within the ICS protocol itself may be used to
obtain UTC timestamps on process measurement data. Since SSP21 (or TLS) seeks to protect this communication using
digital certificates, this feature cannot be used as the primary time source because it would create a circular
dependence.  If a device comes online without time synchronization, and synchronized time is required for securely
setting the time, there is no way to bootstrap communications.

NTP is probably the most common mechanism for synchronizing time, but it requires IP communications to synchronized
endpoints.  The security of NTP has long been an issue.  Most recently, researchers found vulnerabilities in the
[Autokey](https://tools.ietf.org/id/draft-ietf-ntp-bcp-08.html#rfc.section.5.2) security mechanism, leaving users
with pre-shared keys as the only remaining security option.  A replacement for Autokey based on TLS is currently
[underway](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-12).  Since this is based on X.509, it has the
same bootstrapping issue as ICS protocol base time synchronization.

Requiring UTC synchronization for communications introduces significant potential for disruption.  An alternative
approach is presented in this report that constrains certificate validity based on the unsynchronized clocks
of endpoints.

# Applying X.509 to SSP21

SSP21's public key mode uses X25519 Diffie-Hellman (DH) keys as long term identity keys.  The corresponding Ed25519
algorithm was specified for use with SSP21 certificates as a digital signature algorithm (DSA).  These algorithms were
selected for their performance, implementation simplicity, and compact signature sizes. Since SSP21 was specified, X.509
has begin the process of specifying these algorithms for incorporation in [RFC 8410](https://tools.ietf.org/html/rfc8410).
Additionally, it specifies the corresponding DH and DSA algorithms for Curve 448, which has similar properties to
Curve 25519, but with a higher security margin.


```
   id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
   id-X448      OBJECT IDENTIFIER ::= { 1 3 101 111 }
   id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
   id-Ed448     OBJECT IDENTIFIER ::= { 1 3 101 113 }
```

The specification of these algorithms for usage with X.509 enables the usage of X.509 in SSP21.  X.509 tooling such as
the openssl command line, already supports X25519/Ed25519.

```
> openssl version
OpenSSL 1.1.1b  26 Feb 2019

# generate an Ed25519 private key
> openssl genpkey -algorithm Ed25519 -out ed25519.key.pem

# generate a certificate signing request
> openssl req -new -key .\ed25519.key.pem -out certificate.csr

# create a self signed certificate using the CSR and key
> openssl x509 -req -days 14 -in .\certificate.csr -signkey \
  .\ed25519.private.pem -out .\certificate.crt
```

A complete Ed25519 certificate and its decoding can be found in the Appendix.  Since SSP21 uses a DH key
as the identity key for public key modes, the endpoint's certificate must contain a DH key such (e.g. a X25519 key).
This means that self-signed certificates must utilize the [conversion](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
between Ed25519 to X25519 keys. This conversion allows devices to use the same key pay for signing and DH operations.

Where certificate chains using authorities are involved, the final (device) certificate will contain an X25519
key signed by an authority's Ed25519 key.

![Keys in a certificate chain](img/svg/certificate_chain_verification.png){#fig:certificate_chain_verification}

The Ed448/X448 algorithms should be added to SSP21 to provide optional higher security margins than curve 25519, and provide
something to fall back on in the event of cryptographic break in either primitive.

# PKI without UTC

As discussed in the requirements section, UTC time synchronization presents a logistical challenge for remote endpoints and also
a potential for denial of service. In this section, an alternative scheme based on a remote endpoint's unsynchronized clock is
presented. This is acommplished using the mechanisms described in the following subsections.

## Breaking the dependence on UTC

The X.509 RFC explicitly allows for the `notAfter` field to be set to the maximum value.

```
Section 4.1.2.5 Validity

"In some situations, devices are given certificates for which no good
expiration date can be assigned.  For example, a device could be
issued a certificate that binds its model and serial number to its
public key; such a certificate is intended to be used for the entire
lifetime of the device.

To indicate that a certificate has no well-defined expiration date,
the notAfter SHOULD be assigned the GeneralizedTime value of
99991231235959Z."
```

Although not explicitly stated in the RFC, presumably, one could also set the `notBefore` field to the minimum value
of `00000101000000Z` which is synonymous with the beginning of the common era: Year 0, January 1st at 00:00:00. Setting
these two fields to the minimum and maximum value declares that the certificate has no constraints at all based on UTC.

## Device time and boot nonce

All devices, even tiny microcontrollers, are capable of maintaining some measurement of time since boot. This clock ticks
away at some rate that is close to the rate of UTC, but with some drift. When UTC time synchronizaton is involved, UTC time
is typically maintained as some offset from the device's internal clock.

To use the clock in a PKI without UTC, we must couple the time with a `boot nonce`, i.e. a random value that is generated during
device intialization and remains the same unless the device (or comms process) restarts. To ensure that there is a sufficiently
small chance of collisions, the boot nonce shall always be a 256-bit random value pulled from some manner of cryptographically
secure random number generator (CSRNG), such as `/dev/random` on Linux.  This nonce is always paired with the device's clock to
protect against replay attacks against the clock. This is required because when a device restarts, its clock will typically be reset
to zero. However, since the boot nonce changes, this can be detected.

## Abstract protocol

This section present an abstract protocol that a SCADA master might use to procure a certificate to communicate with an endpoint
in the field. The following steps are performed in order:

1. The master informs the authority that it would like to provision a new certificate, and the CA replies with a 256-bit
random nonce that will be used as the certificate serial number (CSN), but also doubles as an identifier for the entire transaction.
The CA records this nonce in an internal database along with the time it processed the request (Ts for "start time").

2. The master requests that the outstation (aka field asset) provide its current device time (Td) and boot nonce (Nb), providing it with the CA's certificate ID.
The outstation replies with the triplet of information {CSN, Td, Nb}, and signs it with its signing key. This triplet plus signature is know as the endpoint time
attestation (ETA).

3. The master creates a certificate signing request (CSR), and includes the ETA as an extension. It sends it to the CA to provision a certificate.

4. The CA receives the CSR, and validates the authenticity of the ETA using the endpoint's public key. The CA calculates that the elapsed
time from Ts to reception of the CSR is within some configurable bounds. The CA verifies that the master's CSR contains a known identity and public key.
If all the checks pass, the CA then issues a certificate with the following contents:

    A) The 'serialNumber' field will contain the CSN identifier originally created by the authority.
	B) The `subject` field will be the name of the master, known to the CA in its internal database.
	C) The `issuer` field will identify the CA, and will match the root certificate(s) installed on the end device.
	D) The `notBefore` and `notAfter` fields will contain the minimum and maximum value respectively.
	E) The certificate will contain a *critical* extension that defines the validity of the certificate in terms of device time and the boot nonce.

The master may then begin to use the certificate to communicate with the endpoint. As part of certifiate validation, endpoints must check that the critical
extension's boot nonce matches the current boot nonce. They may then limit the validity of the certificate relative to their internal clock and the bounds
set within the extension.

# Appendix

## Ed25519 certificate

The contents below are a self-signed certificate using the Ed25519 DSA algorithm.

```
> cat certificate.crt

-----BEGIN CERTIFICATE-----
MIIBNDCB5wIUPS5/LdzOFLOCKQ0tVSY713F2ooIwBQYDK2VwMD0xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJPUjENMAsGA1UEBwwEQmVuZDESMBAGA1UECgwJQXV0b21h
dGFrMB4XDTE5MDgwNzIyMjYzMFoXDTE5MDgyMTIyMjYzMFowPTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAk9SMQ0wCwYDVQQHDARCZW5kMRIwEAYDVQQKDAlBdXRvbWF0
YWswKjAFBgMrZXADIQCFuhZG5NUpxPFeghHDVPqWT97FlNN4FDwqn/2qnJ/1gTAF
BgMrZXADQQDxV48lw3MHaOjUidBT76ql3lFfa3bz3kO/5aoU0X+bzbmIzWLiZEKy
aMXumCfYsvw5t+ku4vRR0er87rtQXvAJ
-----END CERTIFICATE-----

> openssl x509 -in .\certificate.crt -noout -text

Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            3d:2e:7f:2d:dc:ce:14:b3:82:29:0d:2d:55:26:3b:d7:71:76:a2:82
        Signature Algorithm: ED25519
        Issuer: C = US, ST = OR, L = Bend, O = Automatak
        Validity
            Not Before: Aug  7 22:26:30 2019 GMT
            Not After : Aug 21 22:26:30 2019 GMT
        Subject: C = US, ST = OR, L = Bend, O = Automatak
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    85:ba:16:46:e4:d5:29:c4:f1:5e:82:11:c3:54:fa:
                    96:4f:de:c5:94:d3:78:14:3c:2a:9f:fd:aa:9c:9f:
                    f5:81
    Signature Algorithm: ED25519
         f1:57:8f:25:c3:73:07:68:e8:d4:89:d0:53:ef:aa:a5:de:51:
         5f:6b:76:f3:de:43:bf:e5:aa:14:d1:7f:9b:cd:b9:88:cd:62:
         e2:64:42:b2:68:c5:ee:98:27:d8:b2:fc:39:b7:e9:2e:e2:f4:
         51:d1:ea:fc:ee:bb:50:5e:f0:09
```