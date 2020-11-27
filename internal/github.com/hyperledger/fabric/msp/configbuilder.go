/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package msp

import (
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	//"gopkg.in/yaml.v2"
	"github.com/KompiTech/go-toolkit/logging"
)

// OrganizationalUnitIdentifiersConfiguration is used to represent an OU
// and an associated trusted certificate
type OrganizationalUnitIdentifiersConfiguration struct {
	// Certificate is the path to a root or intermediate certificate
	Certificate string `yaml:"Certificate,omitempty"`
	// OrganizationalUnitIdentifier is the name of the OU
	OrganizationalUnitIdentifier string `yaml:"OrganizationalUnitIdentifier,omitempty"`
}

// NodeOUs contains information on how to tell apart clients, peers and orderers
// based on OUs. If the check is enforced, by setting Enabled to true,
// the MSP will consider an identity valid if it is an identity of a client, a peer or
// an orderer. An identity should have only one of these special OUs.
type NodeOUs struct {
	// Enable activates the OU enforcement
	Enable bool `yaml:"Enable,omitempty"`
	// ClientOUIdentifier specifies how to recognize clients by OU
	ClientOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"ClientOUIdentifier,omitempty"`
	// PeerOUIdentifier specifies how to recognize peers by OU
	PeerOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"PeerOUIdentifier,omitempty"`
}

// Configuration represents the accessory configuration an MSP can be equipped with.
// By default, this configuration is stored in a yaml file
type Configuration struct {
	// OrganizationalUnitIdentifiers is a list of OUs. If this is set, the MSP
	// will consider an identity valid only it contains at least one of these OUs
	OrganizationalUnitIdentifiers []*OrganizationalUnitIdentifiersConfiguration `yaml:"OrganizationalUnitIdentifiers,omitempty"`
	// NodeOUs enables the MSP to tell apart clients, peers and orderers based
	// on the identity's OU.
	NodeOUs *NodeOUs `yaml:"NodeOUs,omitempty"`
}

func readFile(file string) ([]byte, error) {
	fileCont, err := ioutil.ReadFile(file)
	if err != nil {
		err = errors.Wrapf(err, "%v reaading file %v failed", logging.FuncInfo(), file)
		return nil, err
	}

	return fileCont, nil
}

func readPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		err = errors.Wrapf(err, "%v reading from file %s failed", logging.FuncInfo(), file)
		return nil, err
	}

	b, _ := pem.Decode(bytes)
	if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
		return nil, errors.Errorf("%v no pem content for file %s", logging.FuncInfo(), file)
	}

	return bytes, nil
}

func getPemMaterialFromDir(dir string) ([][]byte, error) {
	logger := logging.GetLogger()
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = errors.Wrapf(err, "%v directory %v does not exist", logging.FuncInfo(), dir)
		return nil, err
	}

	content := make([][]byte, 0)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "%v could not read directory %s", logging.FuncInfo(), dir)
	}

	for _, f := range files {
		fullName := filepath.Join(dir, f.Name())

		f, err := os.Stat(fullName)
		if err != nil {
			err = errors.Wrapf(err, "%v Failed to stat %s", logging.FuncInfo(), fullName)
			logger.Warn(err.Error())
			continue
		}
		if f.IsDir() {
			continue
		}

		item, err := readPemFile(fullName)
		if err != nil {
			err = errors.Wrapf(err, "%v Failed reading file %s", logging.FuncInfo(), fullName)
			logger.Warn(err.Error())
			continue
		}

		content = append(content, item)
	}

	return content, nil
}

const (
	cacerts              = "cacerts"
	admincerts           = "admincerts"
	signcerts            = "signcerts"
	keystore             = "keystore"
	intermediatecerts    = "intermediatecerts"
	crlsfolder           = "crls"
	configfilename       = "config.yaml"
	tlscacerts           = "tlscacerts"
	tlsintermediatecerts = "tlsintermediatecerts"
)

// SetupBCCSPKeystoreConfig ...
func SetupBCCSPKeystoreConfig(bccspConfig *factory.FactoryOpts, keystoreDir string) *factory.FactoryOpts {
	if bccspConfig == nil {
		bccspConfig = factory.GetDefaultOpts()
	}

	if bccspConfig.ProviderName == "SW" {
		if bccspConfig.SwOpts == nil {
			bccspConfig.SwOpts = factory.GetDefaultOpts().SwOpts
		}

		// Only override the KeyStorePath if it was left empty
		if bccspConfig.SwOpts.FileKeystore == nil ||
			bccspConfig.SwOpts.FileKeystore.KeyStorePath == "" {
			bccspConfig.SwOpts.Ephemeral = false
			bccspConfig.SwOpts.FileKeystore = &factory.FileKeystoreOpts{KeyStorePath: keystoreDir}
		}
	}

	return bccspConfig
}

// GetLocalMspConfigWithType returns a local MSP
// configuration for the MSP in the specified
// directory, with the specified ID and type
func GetLocalMspConfigWithType(dir string, bccspConfig *factory.FactoryOpts, ID, mspType string) (*msp.MSPConfig, error) {
	switch mspType {
	case ProviderTypeToString(FABRIC):
		return GetLocalMspConfig(dir, bccspConfig, ID)
	case ProviderTypeToString(IDEMIX):
		return GetIdemixMspConfig(dir, ID)
	default:
		return nil, errors.Errorf("%v unknown MSP type '%s'", logging.FuncInfo(), mspType)
	}
}

// GetLocalMspConfig ...
func GetLocalMspConfig(dir string, bccspConfig *factory.FactoryOpts, ID string) (*msp.MSPConfig, error) {
	signcertDir := filepath.Join(dir, signcerts)
	keystoreDir := filepath.Join(dir, keystore)
	bccspConfig = SetupBCCSPKeystoreConfig(bccspConfig, keystoreDir)

	err := factory.InitFactories(bccspConfig)
	if err != nil {
		err = errors.Wrapf(err, "%v could not initialize BCCSP Factories", logging.FuncInfo())
		return nil, err
	}

	signcert, err := getPemMaterialFromDir(signcertDir)
	if err != nil || len(signcert) == 0 {
		err = errors.Wrapf(err, "%v could not load a valid signer certificate from directory %s", logging.FuncInfo(), signcertDir)
		return nil, err
	}

	/* FIXME: for now we're making the following assumptions
	1) there is exactly one signing cert
	2) BCCSP's KeyStore has the private key that matches SKI of
	   signing cert
	*/

	sigid := &msp.SigningIdentityInfo{PublicSigner: signcert[0], PrivateSigner: nil}

	return getMspConfig(dir, ID, sigid, &fabric.Certs{})
}

// GetVerifyingMspConfig returns an MSP config given directory, ID and type
func GetVerifyingMspConfig(dir, ID, mspType string, certs *fabric.Certs) (*msp.MSPConfig, error) {
	return getMspConfig(dir, ID, nil, certs)
}

func getMspConfig(dir string, ID string, sigid *msp.SigningIdentityInfo, certs *fabric.Certs) (*msp.MSPConfig, error) {
	caContent := make([][]byte, 0)
	tlsCaContent := make([][]byte, 0)
	for _, cert := range certs.CaCerts {
		caContent = append(caContent, []byte(cert.GetContent()))
		tlsCaContent = append(tlsCaContent, []byte(cert.GetContent()))
	}
	cacerts := caContent
	adminContent := make([][]byte, 0)
	for _, cert := range certs.AdminCerts {
		adminContent = append(adminContent, []byte(cert.GetContent()))
	}
	admincert := adminContent

	intermediatecerts := [][]byte{}
	tlsCACerts := tlsCaContent
	tlsIntermediateCerts := [][]byte{}
	crls := [][]byte{}

	// Load configuration file
	// if the configuration file is there then load it
	// otherwise skip it
	var ouis []*msp.FabricOUIdentifier
	var nodeOUs *msp.FabricNodeOUs
	// Set FabricCryptoConfig
	cryptoConfig := &msp.FabricCryptoConfig{
		SignatureHashFamily:            bccsp.SHA2,
		IdentityIdentifierHashFunction: bccsp.SHA256,
	}

	// Compose FabricMSPConfig
	fmspconf := &msp.FabricMSPConfig{
		Admins:                        admincert,
		RootCerts:                     cacerts,
		IntermediateCerts:             intermediatecerts,
		SigningIdentity:               sigid,
		Name:                          ID,
		OrganizationalUnitIdentifiers: ouis,
		RevocationList:                crls,
		CryptoConfig:                  cryptoConfig,
		TlsRootCerts:                  tlsCACerts,
		TlsIntermediateCerts:          tlsIntermediateCerts,
		FabricNodeOus:                 nodeOUs,
	}

	fmpsjs, _ := proto.Marshal(fmspconf)

	mspconf := &msp.MSPConfig{Config: fmpsjs, Type: int32(FABRIC)}

	return mspconf, nil
}

const (
	IdemixConfigDirMsp                  = "msp"
	IdemixConfigDirUser                 = "user"
	IdemixConfigFileIssuerPublicKey     = "IssuerPublicKey"
	IdemixConfigFileRevocationPublicKey = "RevocationPublicKey"
	IdemixConfigFileSigner              = "SignerConfig"
)

// GetIdemixMspConfig returns the configuration for the Idemix MSP
func GetIdemixMspConfig(dir string, ID string) (*msp.MSPConfig, error) {
	ipkBytes, err := readFile(filepath.Join(dir, IdemixConfigDirMsp, IdemixConfigFileIssuerPublicKey))
	if err != nil {
		err = errors.Wrapf(err, "%v reading issuer public key file failed", logging.FuncInfo())
		return nil, err
	}

	revocationPkBytes, err := readFile(filepath.Join(dir, IdemixConfigDirMsp, IdemixConfigFileRevocationPublicKey))
	if err != nil {
		err = errors.Wrapf(err, "%v reading revocation public key file failed", logging.FuncInfo())
		return nil, err
	}

	idemixConfig := &msp.IdemixMSPConfig{
		Name:         ID,
		Ipk:          ipkBytes,
		RevocationPk: revocationPkBytes,
	}

	signerBytes, err := readFile(filepath.Join(dir, IdemixConfigDirUser, IdemixConfigFileSigner))
	if err == nil {
		signerConfig := &msp.IdemixMSPSignerConfig{}
		err = proto.Unmarshal(signerBytes, signerConfig)
		if err != nil {
			err = errors.Wrapf(err, "%v unmarshaling signer config failed", logging.FuncInfo())
			return nil, err
		}
		idemixConfig.Signer = signerConfig
	}

	confBytes, err := proto.Marshal(idemixConfig)
	if err != nil {
		err = errors.Wrapf(err, "%v marshaling idemix config failed", logging.FuncInfo())
		return nil, err
	}

	return &msp.MSPConfig{Config: confBytes, Type: int32(IDEMIX)}, nil
}
