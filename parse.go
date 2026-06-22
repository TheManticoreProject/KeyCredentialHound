package main

import (
	"encoding/hex"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	"github.com/TheManticoreProject/gopengraph"
	"github.com/TheManticoreProject/gopengraph/edge"
	"github.com/TheManticoreProject/gopengraph/node"
	"github.com/TheManticoreProject/gopengraph/properties"
	"github.com/TheManticoreProject/winacl/sid"
)

// ParseResults populates two graphs from the LDAP results:
//   - og holds the collector's own nodes (KeyCredential, key material) and the
//     intra-collector HasKeyMaterial edges; it carries the source_kind.
//   - ogCrossCollector holds only the HasKeyCredential edges that link existing
//     AD principals to KeyCredential nodes. It must NOT carry a source_kind, so
//     that the referenced AD nodes are never stamped with this collector's kind.
func ParseResults(ldapResults []*ldap.Entry, og *gopengraph.OpenGraph, ogCrossCollector *gopengraph.OpenGraph, debug bool) {
	for _, entry := range ldapResults {
		distinguishedName := entry.GetAttributeValue("distinguishedName")

		// Resolve the account's objectSid once per entry. It is immutable for the
		// lifetime of the principal and is used both as the stable namespace for
		// node ids and as the start of the HasKeyCredential edge.
		rawAccountSid := entry.GetRawAttributeValue("objectSid")
		if len(rawAccountSid) == 0 {
			logger.Warn(fmt.Sprintf("Error: Account SID is empty for account: %s", distinguishedName))
			continue
		}
		accountSid := sid.SID{}
		if _, err := accountSid.Unmarshal(rawAccountSid); err != nil {
			logger.Warn(fmt.Sprintf("Error unmarshalling account SID for account %s: %s", distinguishedName, err))
			continue
		}

		msDsKeyCredentialLinkValues := entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink")
		lenMsDsKeyCredentialLinkValues := len(msDsKeyCredentialLinkValues)

		if debug {
			logger.Info(fmt.Sprintf("Processing %d keycredentials for account: %s", lenMsDsKeyCredentialLinkValues, distinguishedName))
		}

		for id, msDsKeyCredentialLinkValue := range msDsKeyCredentialLinkValues {
			if debug {
				logger.Debug(fmt.Sprintf("[%d/%d] Unmarshalling msDsKeyCredentialLinkValue=%s", id+1, lenMsDsKeyCredentialLinkValues, msDsKeyCredentialLinkValue))
			}

			dnb := ldap.DNWithBinary{}
			_, err := dnb.Unmarshal([]byte(msDsKeyCredentialLinkValue))
			if err != nil {
				if debug {
					logger.Debug(fmt.Sprintf("[%d/%d] Error parsing msDsKeyCredentialLinkValue=%s: %s", id+1, lenMsDsKeyCredentialLinkValues, msDsKeyCredentialLinkValue, err))
				}
				continue
			}

			kc := keycredentiallink.KeyCredentialLink{}
			_, err = kc.Unmarshal(dnb.BinaryData)
			if err != nil {
				if debug {
					logger.Debug(fmt.Sprintf("[%d/%d] Error unmarshalling keyCredentialLinkValue=%s: %s", id+1, lenMsDsKeyCredentialLinkValues, hex.EncodeToString(dnb.BinaryData), err))
				}
				continue
			}

			// Add key credential node to graph. The id is namespaced by the
			// immutable account SID so it stays stable across renames/OU moves.
			keyCredentialNodeId := ""
			if kc.Identifier == "" {
				keyCredentialNodeId = accountSid.String() + "." + fmt.Sprintf("Unknown-%d", id+1)
			} else {
				keyCredentialNodeId = accountSid.String() + "." + kc.Identifier
			}

			// Create key credential node
			p := properties.NewProperties()

			keyCredentialName := kc.Identifier
			if keyCredentialName == "" {
				keyCredentialName = fmt.Sprintf("Unknown-%d", id+1)
			}
			p.SetProperty("name", keyCredentialName)
			p.SetProperty("displayname", keyCredentialName)

			p.SetProperty("identifier", kc.Identifier)
			p.SetProperty("version", kc.Version.String())
			p.SetProperty("source", kc.Source.String())
			p.SetProperty("usage", kc.Usage.String())
			p.SetProperty("creation_time", kc.CreationTime.String())
			p.SetProperty("key_hash", hex.EncodeToString(kc.KeyHash))

			keyCredentialNode, err := node.NewNode(
				keyCredentialNodeId,
				[]string{NodeKindKeyCredential},
				p,
			)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error creating node: %s", err))
				continue
			}
			if !og.AddNode(keyCredentialNode) {
				logger.Warn(fmt.Sprintf("Error adding node kind %s with id=%s for account=%s", NodeKindKeyCredential, keyCredentialNodeId, distinguishedName))
				continue
			}

			// Create key material node
			if kc.KeyMaterial != nil {
				p = properties.NewProperties()
				nodeKind := NodeKindUnknownKeyMaterial
				if _, ok := kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY); ok {
					nodeKind = NodeKindDSAPrivateKey
					p.SetProperty("key_type", "DSA Private Key")

					p.SetProperty("cb_key", kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.CbKey)
					p.SetProperty("count", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.Count[:]))
					p.SetProperty("q", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.Q[:]))
					p.SetProperty("seed", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.Seed[:]))

					p.SetProperty("modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Content.Modulus[:]))
					p.SetProperty("private_exponent", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Content.PrivateExponent[:]))
					p.SetProperty("public", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Content.Public[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY); ok {
					nodeKind = NodeKindDSAPublicKey
					p.SetProperty("key_type", "DSA Public Key")

					p.SetProperty("cb_key", kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.CbKey)
					p.SetProperty("count", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.Count[:]))
					p.SetProperty("q", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.Q[:]))
					p.SetProperty("seed", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.Seed[:]))

					p.SetProperty("modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Content.Modulus[:]))
					p.SetProperty("public", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Content.Public[:]))
					p.SetProperty("generator", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Content.Generator[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY); ok {
					nodeKind = NodeKindRSAPrivateKey
					p.SetProperty("key_type", "RSA Private Key")

					p.SetProperty("bit_length", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.BitLength)
					p.SetProperty("cb_modulus", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbModulus)
					p.SetProperty("cb_prime1", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbPrime1)
					p.SetProperty("cb_prime2", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbPrime2)
					p.SetProperty("cb_public_exp", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbPublicExp)

					p.SetProperty("modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.Modulus[:]))
					p.SetProperty("prime1", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.Prime1[:]))
					p.SetProperty("prime2", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.Prime2[:]))
					p.SetProperty("public_exponent", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.PublicExponent[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY); ok {
					nodeKind = NodeKindRSAPublicKey
					p.SetProperty("key_type", "RSA Public Key")

					p.SetProperty("bit_length", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.BitLength)
					p.SetProperty("cb_modulus", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbModulus)
					p.SetProperty("cb_prime1", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbPrime1)
					p.SetProperty("cb_prime2", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbPrime2)
					p.SetProperty("cb_public_exp", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbPublicExp)

					p.SetProperty("modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Content.Modulus[:]))
					p.SetProperty("public_exponent", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Content.PublicExponent[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY); ok {
					nodeKind = NodeKindECCPrivateKey
					p.SetProperty("key_type", "ECC Private Key")

					p.SetProperty("key_size", kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Header.KeySize)

					p.SetProperty("d", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Content.D[:]))
					p.SetProperty("x", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Content.X[:]))
					p.SetProperty("y", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Content.Y[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY); ok {
					nodeKind = NodeKindECCPublicKey
					p.SetProperty("key_type", "ECC Public Key")

					p.SetProperty("key_size", kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY).Header.KeySize)

					p.SetProperty("x", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY).Content.X[:]))
					p.SetProperty("y", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY).Content.Y[:]))

				}

				keyMaterialName := p.GetProperty("key_type", "Unknown Key Material")
				p.SetProperty("name", keyMaterialName)
				p.SetProperty("displayname", keyMaterialName)

				keyNodeId := ""
				if kc.Identifier == "" {
					keyNodeId = keyCredentialNodeId + "." + nodeKind
				} else {
					keyNodeId = kc.Identifier + "." + nodeKind
				}
				if og.GetNode(keyNodeId) == nil {
					// If it doesn't exist, create it, else that means another identical key material already exists.
					keyNode, err := node.NewNode(
						keyNodeId,
						[]string{nodeKind},
						p,
					)
					if err != nil {
						logger.Warn(fmt.Sprintf("Error creating node: %s", err))
						continue
					}
					if !og.AddNode(keyNode) {
						logger.Warn(fmt.Sprintf("Error adding node kind %s with id=%s for account=%s", nodeKind, keyNodeId, distinguishedName))
						continue
					}
				}

				// Create has key credential edge
				hasKeyMaterialEdge, err := edge.NewEdge(
					keyCredentialNodeId,
					keyNodeId,
					EdgeKindHasKeyMaterial,
					properties.NewProperties(),
				)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error creating edge kind %s from %s to %s: %s", EdgeKindHasKeyMaterial, keyCredentialNodeId, keyNodeId, err))
					continue
				}
				if !og.AddEdge(hasKeyMaterialEdge) {
					logger.Warn(fmt.Sprintf("Error adding edge: (%s)---[%s]-->(%s)", keyCredentialNodeId, EdgeKindHasKeyMaterial, keyNodeId))
					continue
				}
			}

			// Create has key credential edge. This is a cross-collector edge to a
			// pre-existing AD principal, so it goes into the separate graph that
			// carries no source_kind (see the two-step upload note above).
			hasKeyCredentialEdge, err := edge.NewEdge(
				accountSid.String(),
				keyCredentialNodeId,
				EdgeKindHasKeyCredential,
				properties.NewProperties(),
			)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error creating edge: %s", err))
				continue
			}
			// We don't validate the edge here because its a hybrid edge (the SID is not a node in this graph).
			if !ogCrossCollector.AddEdgeWithoutValidation(hasKeyCredentialEdge) {
				logger.Warn(fmt.Sprintf("Error adding edge: (%s)---[%s]-->(%s)", accountSid.String(), EdgeKindHasKeyCredential, keyCredentialNodeId))
				continue
			}
		}
	}
}
