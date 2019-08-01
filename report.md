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
* Any extensions specified for usage in X.509 could also be applied to Transport Layer Security (TLS)
* X.509 already has an ecosystem of tools that can either be directly reused or adapted to purpose.

