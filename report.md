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
# OpenSSL 1.1.1b  26 Feb 2019

# generate an Ed25519 private key
> openssl genpkey -algorithm Ed25519 -out ed25519.key.pem

# generate a certificate signing request
> openssl req -new -key .\ed25519.key.pem -out certificate.csr

# create a self signed certificate using the CSR and key
> openssl x509 -req -days 14 -in .\certificate.csr -signkey \
  .\ed25519.private.pem -out .\certificate.crt
```