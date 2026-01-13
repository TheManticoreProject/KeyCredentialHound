package main

const (
	KindKeyCredentialBase = "KeyCredentialBase"

	EdgeKindHasKeyCredential = "HasKeyCredential"
	EdgeKindHasKeyMaterial   = "HasKeyMaterial"

	NodeKindKeyCredential = "KeyCredential"

	NodeKindUnknownKeyMaterial = "KeyCredentialUnknownKeyMaterial"

	NodeKindDSAPrivateKey = "KeyCredentialDSAPrivateKey"
	NodeKindRSAPrivateKey = "KeyCredentialRSAPrivateKey"
	NodeKindDSAPublicKey  = "KeyCredentialDSAPublicKey"
	NodeKindRSAPublicKey  = "KeyCredentialRSAPublicKey"
	NodeKindECCPrivateKey = "KeyCredentialECCPrivateKey"
	NodeKindECCPublicKey  = "KeyCredentialECCPublicKey"
)
