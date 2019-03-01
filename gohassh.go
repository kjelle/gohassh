package gohassh

// HASSH is a method developed by Salesforce (se github.com/salesforce/hassh):
//
//     "hassh" and "hasshServer" are MD5 hashes constructed from a specific set of algorithm,s that are supported
//     by various SSH Client and Server Applications. These algorithms are exchanged after the initial TCP three-way
//     handshake as clear-text packets known as "SSH_MSG_KEXINIT" messages, and are an integral part of the setup
//     of the final encrypted SSH channel. The existence and ordering of these algorithms is unique enough such that
//     it can be used as a fingerprint to help identify the underlying Client and Server application or unique
//     implementation, regardless of higher level ostensible identifiers such as "Client" or "Server" strings.
