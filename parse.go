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

func ParseResults(ldapResults []*ldap.Entry, og *gopengraph.OpenGraph, debug bool) {
	for _, entry := range ldapResults {
		distinguishedName := entry.GetAttributeValue("distinguishedName")
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

			// Add key credential node to graph
			keyCredentialNodeId := ""
			if kc.Identifier == "" {
				keyCredentialNodeId = fmt.Sprintf("Unknown-%d", id+1) + "." + distinguishedName
			} else {
				keyCredentialNodeId = kc.Identifier + "." + distinguishedName
			}

			// Create key credential node
			p := properties.NewProperties()

			p.SetProperty("displayName", kc.Identifier)

			p.SetProperty("Identifier", kc.Identifier)
			p.SetProperty("Version", kc.Version.String())
			p.SetProperty("Source", kc.Source.String())
			p.SetProperty("Usage", kc.Usage.String())
			p.SetProperty("CreationTime", kc.CreationTime.String())
			p.SetProperty("KeyHash", hex.EncodeToString(kc.KeyHash))

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
					p.SetProperty("KeyType", "DSA Private Key")

					p.SetProperty("CbKey", kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.CbKey)
					p.SetProperty("Count", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.Count[:]))
					p.SetProperty("Q", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.Q[:]))
					p.SetProperty("Seed", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Header.Seed[:]))

					p.SetProperty("Modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Content.Modulus[:]))
					p.SetProperty("PrivateExponent", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Content.PrivateExponent[:]))
					p.SetProperty("Public", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PRIVATE_KEY).Content.Public[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY); ok {
					nodeKind = NodeKindDSAPublicKey
					p.SetProperty("KeyType", "DSA Public Key")

					p.SetProperty("CbKey", kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.CbKey)
					p.SetProperty("Count", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.Count[:]))
					p.SetProperty("Q", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.Q[:]))
					p.SetProperty("Seed", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Header.Seed[:]))

					p.SetProperty("Modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Content.Modulus[:]))
					p.SetProperty("Public", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Content.Public[:]))
					p.SetProperty("Generator", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_DSA_PUBLIC_KEY).Content.Generator[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY); ok {
					nodeKind = NodeKindRSAPrivateKey
					p.SetProperty("KeyType", "RSA Private Key")

					p.SetProperty("BitLength", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.BitLength)
					p.SetProperty("CbModulus", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbModulus)
					p.SetProperty("CbPrime1", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbPrime1)
					p.SetProperty("CbPrime2", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbPrime2)
					p.SetProperty("CbPublicExp", kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Header.CbPublicExp)

					p.SetProperty("Modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.Modulus[:]))
					p.SetProperty("Prime1", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.Prime1[:]))
					p.SetProperty("Prime2", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.Prime2[:]))
					p.SetProperty("PublicExponent", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PRIVATE_KEY).Content.PublicExponent[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY); ok {
					nodeKind = NodeKindRSAPublicKey
					p.SetProperty("KeyType", "RSA Public Key")

					p.SetProperty("BitLength", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.BitLength)
					p.SetProperty("CbModulus", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbModulus)
					p.SetProperty("CbPrime1", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbPrime1)
					p.SetProperty("CbPrime2", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbPrime2)
					p.SetProperty("CbPublicExp", kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Header.CbPublicExp)

					p.SetProperty("Modulus", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Content.Modulus[:]))
					p.SetProperty("PublicExponent", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Content.PublicExponent[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY); ok {
					nodeKind = NodeKindECCPrivateKey
					p.SetProperty("KeyType", "ECC Private Key")

					p.SetProperty("KeySize", kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Header.KeySize)

					p.SetProperty("D", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Content.D[:]))
					p.SetProperty("X", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Content.X[:]))
					p.SetProperty("Y", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PRIVATE_KEY).Content.Y[:]))

				} else if _, ok := kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY); ok {
					nodeKind = NodeKindECCPublicKey
					p.SetProperty("KeyType", "ECC Public Key")

					p.SetProperty("KeySize", kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY).Header.KeySize)

					p.SetProperty("X", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY).Content.X[:]))
					p.SetProperty("Y", hex.EncodeToString(kc.KeyMaterial.(*keys.BCRYPT_ECC_PUBLIC_KEY).Content.Y[:]))

				}
				keyNodeId := kc.Identifier + "." + nodeKind
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

			// Create account SID node
			rawAccountSid := entry.GetRawAttributeValue("objectSid")
			if len(rawAccountSid) == 0 {
				logger.Warn(fmt.Sprintf("Error: Account SID is empty for account: %s", distinguishedName))
				continue
			}
			accountSid := sid.SID{}
			_, err = accountSid.Unmarshal(rawAccountSid)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error unmarshalling account SID: %s", err))
				continue
			}

			// Create has key credential edge
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
			if !og.AddEdgeWithoutValidation(hasKeyCredentialEdge) {
				logger.Warn(fmt.Sprintf("Error adding edge: (%s)---[%s]-->(%s)", accountSid.String(), EdgeKindHasKeyCredential, keyCredentialNodeId))
				continue
			}
		}
	}
}
