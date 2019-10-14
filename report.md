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
and its extensions contain an abundance of information not relevant to many control systems, and the format is encoded 
using ASN.1 DER which is rather complex compared to alternatives.  All of these challenges with X.509 remain true, however, 
the benefits now seem to outweigh the issues, namely:

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

* The links may be highly bandwidth constrained

## Time Synchronization

X.509 constrains the validity of the certificate using the *notBefore* and *notAfter* fields, each of which specifies
a UTC timestamp.  When issuing these certificates, certificate authorities (CAs) use the fields to define the lifetime
of the certificate, explicitly relying on the availability of UTC time synchronization for verifying them.  This
reliance can be problematic as it introduces additional attack surface, namely:

* A denial of service (DoS) on the time synchronization mechanism can now disrupt communications. Introducing the usage
of certificates ironically makes the system more vulnerable to disruption.

* If time synchronization can be manipulated, the lifetime of certificates can be improperly manipulated.

It is not uncommon for ICS networks to use some form of time synchronization, but it is usually not critical to
maintaining or monitoring operations.  For example, electric power systems frequently use one of the 
[IRIG](http://irig.org/) standards to synchronize time on protective relays to UTC with sub-cycle precision.
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
has begun specifying these algorithms for incorporation in [RFC 8410](https://tools.ietf.org/html/rfc8410).
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
between Ed25519 to X25519 keys. This conversion allows devices to use the same key pair for signing and DH operations.

Where certificate chains using authorities are involved, the final (device) certificate will contain an X25519
key signed by an authority's Ed25519 key.

![Keys in a certificate chain](img/svg/certificate_chain_verification.png){#fig:certificate_chain_verification}

The Ed448/X448 algorithms should be added to SSP21 to provide optional higher security margins than curve 25519, and provide
something to fall back on in the event of cryptographic break in either primitive.

# PKI without UTC

As discussed in the requirements section, UTC time synchronization presents a logistical challenge for remote endpoints and also
a potential for denial of service. In this section, an alternative scheme based on a remote endpoint's unsynchronized clock is
presented. This is accomplished using the mechanisms described in the following subsections.

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
away at some rate that is close to the rate of UTC, but with some drift. When UTC time synchronization is involved, UTC time
is typically maintained as some offset from the device's internal clock.

To use the clock in a PKI without UTC, we must couple the time with a `boot nonce`, i.e. a random value that is generated during
device initialization and remains the same unless the device (or comms process) restarts. To ensure that there is a sufficiently
small chance of collisions, the boot nonce shall always be a 256-bit random value pulled from some manner of cryptographically
secure random number generator (CSRNG), such as `/dev/random` on Linux.  This nonce is always paired with the device's clock to
protect against replay attacks against the clock. This is required because when a device restarts, its clock will typically be reset
to zero. However, since the boot nonce changes, this can be detected.

## Abstract protocol

This section present an abstract protocol that a SCADA master might use to procure a certificate to communicate with an outstation
in the field.

1. The master makes a request to the authority asking for a new transaction identifier (TID).

2. The CA replies with a 256-bit random TID. The CA records this nonce in memory along with the time it processed the request (Ts for "start time").

3. The master makes a request to the outstation for attestation of its current device time (Td) and boot nonce (N), providing it with the TID from the authority.

4. The outstation replies with the triplet of information {TID, Td, N}  and signs it with its private key. This triplet plus signature is know as the TimeAttestationResponse (TAR).

5. The master creates a certificate signing request (CSR) including the TAR as a requested X.509 extension. It sends it to the CA to provision a certificate. The CSR is the DER
encoded PKCS #10 CSR object. The "attributes" element of this object is capable of carrying the TAR as a requested extension.

6. The CA processes the CSR and validates the authenticity of both the CSR itself, and the TAR using the master and outstation public keys. The CA calculates the elapsed
time from Ts to reception of the CSR is within some configurable limit. If all the checks pass, the CA then issues a certificate with the following contents:

    A) The 'serialNumber' field will contain the CSN identifier originally created by the authority.
	B) The `subject` field will be the name of the master, known to the CA in its internal database.
	C) The `issuer` field will identify the CA, and will match the root certificate(s) installed on the end device.
	D) The `notBefore` and `notAfter` fields will contain the minimum and maximum value respectively.
	E) The certificate will contain a extension that defines the validity of the certificate in terms of device time and the boot nonce. This
	   extension must always be marked as **critical** in the extension envelope.

The master may then begin to use the certificate to communicate with the outstation. As part of certificate validation, outstations must check that the critical
extension's boot nonce matches the current boot nonce. They must then limit the validity of the certificate relative to their internal clock and the bounds
set within the extension.

The following figure illustrates the process described above. The notation below assumes that the protocol is implemented as a REST API 
passing binary objects back and forth as the request and response payloads.

![Certificate provisioning protocol](img/msc/protocol.png){#fig:certificate_provisioning_protocol}

## Security discussion

This section discusses the security of the abstract protocol presented in the previous section. This "protocol" is actually two different mechanisms working
together to procure a certificate independent from UTC time synchronization.

The first mechanism is a simple request/response protocol between the client (master) and the authority.  The first request/response (steps 1 & 2) that retrieves 
a fresh certificate/transaction identifier doesn't necessarily require any cryptographic protection. Anyone could request a new identifier, but would be unable
to produce a properly signed CSR in step #5 that would lead to a valid certificate being issued. A man-in-the-middle (MitM) could manipulate the 
certificate ID returned by the authority, to a pre-observed or non-existing ID. At worst, this would result in a denial of service (DoS) which a MitM
can always perform against a cryptographic protocol by causing authentication mechanism to fail.

Step #5 sends a CSR to the authority which is cryptographically signed using the master's public key and verifiable by the authority. This protects the contents 
of the message from any modification. Similarly, the certificate returned in step #6 is cryptographically signed by the authority and verifiable by the master.
Unless confidentiality is required for 1/2 or 3/4, no further security mechanisms are required.

Step 3 is a request from the master to the outstation asking for its current time and boot nonce.  Without integrity protection, a MitM could alter the ID
in the request, but just as in 1) all an attacker can really do in this situation is perform a DoS. If the master receives a response object containing an ID
other than the one it requested, it is easily detected. The response in step 4 containing the OTA is signed by the outstation's private key, and cannot be manipulated
without detection by the authority when it processes the object inside the CSR submitted by the master.

### Confidentiality

The discussion above assumes that the confidentiality of the enrollment process is of little importance, namely that passive observability of the contents of
the exchanged messages is more important than any loss of privacy. Nevertheless, options exist that could provide both confidentiality and additional
integrity for certain message exchanges, such as SCEP (below) for protecting exchanges 5/6.

### Simple Certificate Enrollment Protocol (SCEP)

[SCEP](https://www.ietf.org/id/draft-gutmann-scep-14.txt) is a protocol designed (among other things) to handle the enrollment process defined in steps 5 and 6.
SCEP allows for the signing and encryption of all of the messages exchanged between a client and an authority. Is it to be determined whether the complexity of SCEP
is worth the effort, nevertheless, the basic idea of exchanging the request/response objects using HTTP and a REST API is an attractive choice since the technology
and frameworks for implementing it are ubiquitous.

SCEP could be easily extended with new message types to implement exchanges 1/2, while simultaneously providing confidentiality.

## Message and extension definitions

This section provides concrete ASN.1 definitions for the message payloads and embedded extensions defined in the abstract protocol above.

Before defining the individual message types, we define the following ASN.1 sub-types and type aliases that are used in multiple messages:

```
-- all random nonces are 256-bits in length --
Nonce256 ::= OCTET STRING (SIZE(32))

-- define aliases for specific types of nonces --
TransactionIdentifier ::= Nonce256
BootNonce ::= Nonce256

-- relative device time is measured in milliseconds as an unsigned 64-bit number --
-- 2^64 - 1 == 18446744073709551615
DeviceTimestamp ::= INTEGER(0 .. 18446744073709551615)
```

### TransactionIdRequest (1)

This request contains no payload. If implemented over a REST API, the client simply makes an HTTP POST request to a specific URL.

### TransactionIdResponse (2)

The response data is the DER encoded bytes of the following ASN.1 object definition.

```
TransactionIdResponse ::= SEQUENCE
{
    -- random 256-bit transaction identifier generated by the authority --
    tid     TransactionIdentifier,
    -- the number of milliseconds for which the TID will remain valid --
    validForMs   DeviceTimestamp
}
```

The `validForMs` field indicates the number of milliseconds for which the TID will remain valid. It is informational only, and is
meant to help in debugging any subsequent enrollment requests that fail due to a timeout.

### TimeAttestationRequest (3)

This request message only carries the TID to the outstation for signing purposes.

```
TimeAttestationRequest ::= SEQUENCE
{
    tid    TransactionIdentifier
}
```

### TimeAttestationResponse (4)

The attestation response uses the same signed structure and algorithm identifiers as a CSR or X.509 certificate.

```
-- this type is used in X.509 and PKCS #10 to identify a signing algorithm --
AlgorithmIdentifier  ::=  SEQUENCE
{
        algorithm     OBJECT IDENTIFIER
        parameters    ANY DEFINED BY algorithm OPTIONAL
}

-- the actual to-be-signed (TBS) structure --
TBSTimeAttestation ::= SEQUENCE
{
   tid             TransactionIdentifier,
   deviceTimeMs    DeviceTimestamp,
   bootId          BootNonce
}

-- the outer envelope for the signed inner data --
TimeAttestationResponse ::= SEQUENCE
{
   tbsTimeAttestation    TBSTimeAttestation,
   algorithm             AlgorithmIdentifier,
   signatureValue        BIT STRING
}
```

### PKCS #10 CSR (5)

The ASN.1 structure of a CSR is defined in PKCS #10 whose definition is also replicated in [RFC 2986](https://tools.ietf.org/html/rfc2986). It allows
for arbitrary attributes to be embedded, including extension requests. The CSR format can be privately extended to carry arbitrary data, in this case
carrying the TimeAttestation response from 4) indicating that the master is requesting an extension in the X.509 certificate that bounds its validity
based on the device time and the boot nonce.

### X.509 Certificate (6)

The returned X.509 certificate shall contain an extension with an OID that would need to be registered through the IANA. The extension shall
always be marked "critical" in the extension envelope:

```
-- from RFC 5280 --
Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
```

The `extnValue` is then the DER encoding of the following ASN.1 sequence:

```
DeviceTimeValidity ::= SEQUENCE
{
    bootId          BootNonce
	notBefore       DeviceTimestamp
	notAfter        DeviceTimestamp
}
```

The `notBefore` and `notAfter` have the same general meaning as the fields with the same names in the
X.509 `Validity` structure. The difference is that the bounds apply to relative device time and only
to a particular device initialization or boot.

# Revocation

Systems that issue digital certificates must enviably address revocation of those certificates. Possible
reasons for revoking a certificate include the disclosure of private keys or the accidental issuance of the
certificate in the first place.

## Methods of revocation

Revocation has historically been one of the trickiest parts of managing a PKI. In the following sections three
different methods of revocation are discussed and their trade-offs analyzed within the context of ICS.

### Certificate Revocation Lists (CRLs)

CRLs are a digitally signed artifact that names certificates revoked prior to the scheduled expiration time.  CRLs
are published by an authority, and distributed to the users of certificates issued by that authority. Using CRLs 
for revocation puts the onus on the user of a certificate to periodically check a "distribution point" for the CRL that
is either preconfigured, or named in the certificate itself. CRLs are not a great solution in SCADA for several reasons.

Periodically requesting a CRL at an outstation is problematic from a network perspective.  Many field assets have 
limited communication bandwidth, but more importantly may not have general purpose networking at all, such as non-IP
transports like 900mhz radio or serial. As such, CRLs are not a workable solution at the outstation for checking the
validity of certificates issued to master stations. One could imagine a scheme whereby the master periodically "pushes"
CRLs to the outstation, but this puts the subject of a certificate in charge of distributing its own revocation, an 
obvious cryptographic conflict of interest.

CRLs may be practical from the master(s) to an authority as these lines of communication will be IP-based and typically
have much higher bandwidth to easily support this communication, however, more integrated alternatives to the CRL exist.

### Online Certificate Status Protocol (OCSP)

OCSP ([RFC 6960](https://tools.ietf.org/html/rfc6960])) was designed to address some of the issues with CRLs. Using OCSP,
clients make a call to an authority to obtain the status of a certificate as part of the process of validating it. This 
approach is more 'event driven' and thus reduces network overheads. OCSP is syntactically less complicated than using CRLs
which reduces the possibility of security bugs in the parsing itself.

Nevertheless, using OCSP at the outstation requires IP connectivity at the outstation and access to an OCSP responder
(i.e. the authority) at the outstation. Failing to be able to reach the OCSP responder would also result in a denial-of-service
and failure to establish communications. OCSP has all of the same problems as CRLs at the field asset.

Another interesting difference between IT and OT is that OT communications typically last indefinitely. TCP sessions generally
stay 'connected' for extremely long periods of time without interruption.  Using OCSP might only force a party to
revalidate the status of the peer certificate during TLS/SSP21 renegotiation since the TCP session stays up indefinitely.

This means that, practically speaking, OCSP provides no more timely a means of revoking a certificate than just having 
short-lived certificates for master-to-field communications.

### Fast-expiration

Fast expiration is the practice of issuing certificates that only have a relativity short validity (UTC or UTC-less). If
one or both ends of the connection is forced to periodically renew certificates, no explicit revocation is required at all.
The process of revoking a certificate is simply setting some information in the authority telling it to no longer issue
new certificates for a particular entity.

If the duration of validity for such certificates is on the same order as CRL or OCSP polling, than fast-expiration can 
'revoke' certificates with the same level of expediency, but doesn't require additional communications for the purpose of 
validating the status of certificates. Instead, the onus is put on the entity presenting the certificate to periodically
obtain a new certificate. This scheme works particularly well for certificates where the SCADA master is the subject, 
removing all burden on field assets to use the network to check their validity.

## Hybrid approach

Fast-expiration should be default method for revoking certificates issued to masters. Masters have the 
network connectivity and bandwidth making it possible to periodically procure new certificates from an authority. As this
will be the only mechanism for revoking master certificates, the CA should issue certificates to masters with validity
lasting hours, not days, months, or years. Fast-expiration can be used in conjunction with the UTC-less PKI scheme presented
earlier. CAs should issue short lived certificates to masters based on the device clock of the field asset with which
they want to communicate.

On the other hand, outstation certificates must last for the practical lifetime of the device (years). These certificates
may be based on UTC, as it's reasonable to assume that the CA and master stations can maintain UTC time synchronization 
on the enterprise network. It's much easier to protect this relatively small collection of nodes from disruption and attack
than it is to protect the time synchronization of an entire system across a broad geographical area.

Given that outstation certificates must last a long time, their revocation must be performed using either a CRL or OCSP. OCSP
is the simpler, more modern approach, and sufficient bandwidth should exist between master stations and an in-house
authority.

## Clock Skew

When issuing certificates to masters, system admins must also consider the possibility of outstation clock skew since
it is not utilizing synchronization. When certificates are refreshed every hour or so, a fresh time attestation is 
retrieved, and any clock skew that built up previously is effectively zeroed. Even if the the device clock on the field asset
ticks at a rate that differs as much as 2% from the CA, that only amounts to a 72 second difference over the course 
of an hour. Masters should be allowed to retrieve certificates with slight overlap to prevent a loss of communications due
to clock skew or other disruption. If masters always try to procure certificates in advance of their scheduled expiration,
communications can be maintained without any concern over skew.



# Standardization & Recommendations

The concepts discussed within this report are actionable via outreach to several external groups outside CES21. Prior to 
submitting anything to a standards body, it is recommended that this report be shared with vendor partners that will most
definitely have an interest and a stake in seeing this type of a PKI brought to production environments.

The core concepts around a UTC-less PKI would require the registration of unique identifiers (OIDs) via the IETF and the 
IANA. That said, it is recommended that this report be shared with the IEC TC 57 which publishes the IEC 62351 series of 
standards. IEC 62351-3 is of particular interest here in that it already covers the usage of TLS within a power systems
context. This standard makes few ICS-specific recommendations, mostly focusing on compatibility at the level of cipher 
suites and  renegotiation settings.  It makes no recommendation on the period of validity for certificates, how to do PKI
without UTC, or how to address enrollment in a fast expiration scheme.  Doing the standardization of the X.509 extensions
and time  attestation exchanges are independent from SSP21.

Prototyping the concepts outlined in this report in the SSP21 reference implementation is also desirable should suitable 
funding be identified in the future. Implementing the following would provide feedback during the standardization process:

* Implement X.509 handling in SSP21 reference implementation
* Extend the implementation with messages for time attestation
* Add device time based processing to an open source CA, such as [EJBCA](https://www.ejbca.org/)

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