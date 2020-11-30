/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resource

import (
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"time"
    "strings"
	"github.com/golang/protobuf/proto"
	fabric "github.com/KompiTech/manblock-fabric-orchestrator/pkg/fabric/model"
	"github.com/KompiTech/go-toolkit/logging"
	ppb "github.com/KompiTech/grpc-apis/manblock-common"
	"go.uber.org/zap"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"context"
	ob "github.com/hyperledger/fabric-protos-go/orderer"

	"github.com/jiribroulik/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/channelconfig"
	utils "github.com/jiribroulik/fabric-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/jiribroulik/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/encoder"
	//"github.com/jiribroulik/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxlator/update"
	"github.com/pkg/errors"

	"github.com/jiribroulik/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/genesisconfig"

	//"github.com/hyperledger/fabric-config/protolator"
	//"github.com/hyperledger/fabric-protos-go/common"
	cb "github.com/hyperledger/fabric-protos-go/common"
	//"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource/genesisconfig"
)

// See https://github.com/hyperledger/fabric/blob/be235fd3a236f792a525353d9f9586c8b0d4a61a/cmd/configtxgen/main.go

const (
	anchorPeerPort         = 7051
	maxMessageCount        = 10
	absoluteMaxBytes       = 10 * 1024 * 1024
	preferredMaxBytes      = 512 * 1024
	batchTimeout           = 2 * time.Second
	consortiumName         = "PlatformOrdererConsortium"
	ordererType            = "etcdraft"
	ordererSystemChannelID = "ordsyschannel"
	// OrdererCapabilities ...
	OrdererCapabilities = "V2_0"
	// ApplicationCapabilities ...
	ApplicationCapabilities = "V2_0"
	// SystemChannelCapabilities ...
	SystemChannelCapabilities = "V2_0"
)

func doOutputBlock(config *genesisconfig.Profile, channelID string, certs *fabric.Certs, policy *ppb.FabricPolicy) ([]byte, error) {
	logger := logging.GetLogger()
	pgen := encoder.New(config)
	if config.Consortiums == nil {
		logger.Warn("Genesis block does not contain a consortiums group definition.  This block cannot be used for orderer bootstrap.")
	}
	genesisBlock := pgen.GenesisBlockForChannel(channelID)
	if genesisBlock == nil {
		return nil, errors.Errorf("%v Error generating orderer channel genesis block", logging.FuncInfo())
	}
	genesisBlockBytes := utils.MarshalOrPanic(genesisBlock)
	if genesisBlockBytes == nil {
		return nil, errors.Errorf("%v Error marshaling genesis block", logging.FuncInfo())
	}
	return genesisBlockBytes, nil
}

func doOutputChannelCreateTx(profile *genesisconfig.Profile, channelID string, certs *fabric.Certs, ordererEndpoints map[string][]string, policy *ppb.FabricPolicy) ([]byte, error) {
	configtx, err := encoder.MakeChannelCreationTransaction(channelID, nil, profile)
	if err != nil {
		err = errors.Wrapf(err, "%v channel creation transaction failed", logging.FuncInfo())
		return nil, err
	}
	cBytes := utils.MarshalOrPanic(configtx)
	if cBytes == nil {
		return nil, errors.Errorf("%v Error marshaling application org channel genesis block tx", logging.FuncInfo())
	}
	return cBytes, nil
}

// func getOrgConfigGroup(profile *genesisconfig.Profile, mgr *fabric.Manager) (*cb.ConfigGroup, error) {
// 	ag, err := encoder.NewOrdererOrgGroup(profile.Application.Organizations[0], setup)
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "bad application definition for org")
// 	}
// 	return ag, nil
// }

func getOrgPolicies(orgName string, customPolicies *ppb.OrgPolicy) map[string]*genesisconfig.Policy {
	policies := getCustomPolicies(customPolicies.GetPolicies())
	// policies := make(map[string]*genesisconfig.Policy)
	if _, ok := policies["Readers"]; !ok {
		policies["Readers"] = &genesisconfig.Policy{Type: "Signature", Rule: "OR('" + orgName + ".member')"}
	}
	if _, ok := policies["Writers"]; !ok {
		policies["Writers"] = &genesisconfig.Policy{Type: "Signature", Rule: "OR('" + orgName + ".member')"}
	}
	if _, ok := policies["Admins"]; !ok {
		policies["Admins"] = &genesisconfig.Policy{Type: "Signature", Rule: "OR('" + orgName + ".admin')"}
	}
	return policies
}

func getImplicitMetaPolicies(customPolicies map[string]*ppb.Policy) map[string]*genesisconfig.Policy {
	policies := getCustomPolicies(customPolicies)
	// policies := make(map[string]*genesisconfig.Policy)
	if _, ok := policies["Readers"]; !ok {
		policies["Readers"] = &genesisconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Readers"}
	}
	if _, ok := policies["Writers"]; !ok {
		policies["Writers"] = &genesisconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Writers"}
	}
	if _, ok := policies["Admins"]; !ok {
		policies["Admins"] = &genesisconfig.Policy{Type: "ImplicitMeta", Rule: "MAJORITY Admins"}
	}
	return policies
}

func getOrdererPolicies(customPolicies map[string]*ppb.Policy) map[string]*genesisconfig.Policy {
	// set defaults
	policies := getImplicitMetaPolicies(customPolicies)
	if _, ok := policies["BlockValidation"]; !ok {
		policies["BlockValidation"] = &genesisconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Writers"}
	}
	return policies
}

func getCustomPolicies(customPolicies map[string]*ppb.Policy) map[string]*genesisconfig.Policy {
	policies := make(map[string]*genesisconfig.Policy)
	if len(customPolicies) > 0 {
		for k, v := range customPolicies {
			policies[k] = &genesisconfig.Policy{Type: v.Type, Rule: v.Rule}
		}
	}
	return policies
}

func getChannelAcls(customACLPolicies map[string]string) map[string]string {
	acls := make(map[string]string)
	for k, v := range customACLPolicies {
		acls[k] = v
	}
	// set defaults for the rest and non set keys
	defaultACLPolicies := "lscc/ChaincodeExists: /Channel/Application/Readers,lscc/GetDeploymentSpec: /Channel/Application/Readers,lscc/GetChaincodeData: /Channel/Application/Readers,lscc/GetInstantiatedChaincodes: /Channel/Application/Readers,qscc/GetChainInfo: /Channel/Application/Readers,qscc/GetBlockByNumber: /Channel/Application/Readers,qscc/GetBlockByHash: /Channel/Application/Readers,qscc/GetTransactionByID: /Channel/Application/Readers,qscc/GetBlockByTxID: /Channel/Application/Readers,cscc/GetConfigBlock: /Channel/Application/Readers,cscc/GetConfigTree: /Channel/Application/Readers,cscc/SimulateConfigTreeUpdate: /Channel/Application/Readers,peer/Propose: /Channel/Application/Writers,peer/ChaincodeToChaincode: /Channel/Application/Readers,event/Block: /Channel/Application/Readers,event/FilteredBlock: /Channel/Application/Readers"
	ss := strings.Split(defaultACLPolicies, ",")
	for _, pair := range ss {
		z := strings.Split(pair, ":")
		if _, ok := acls[z[0]]; !ok { // if key does not exist in the map
			acls[z[0]] = z[1]
		}
	}
	return acls
}

func getApplicationOrg(org *ppb.Organization, policy *ppb.FabricPolicy) *genesisconfig.Organization {
	if policy == nil {
		policy = &ppb.FabricPolicy{}
	}

	policies := getOrgPolicies(org.GetMspId(), policy.GetOrgPolicies()[org.GetMspId()])
	return &genesisconfig.Organization{
		Name:     org.GetMspId(),
		ID:       org.GetMspId(),
		Policies: policies,
	}
}

func getApplicationOrgWithAnchors(org *ppb.Organization, policy *ppb.FabricPolicy, peers []*ppb.Peer) *genesisconfig.Organization {
	logger := logging.GetLogger()
	peerOrg := getApplicationOrg(org, policy)
	var anchorPeers []*genesisconfig.AnchorPeer

	logger.Debug("Anchor peers in channel", zap.Any("peers", peers))

	for _, peer := range peers {
		if peer.GetAnchor() {
			anchorPeers = append(anchorPeers, &genesisconfig.AnchorPeer{
				Host: peer.GetCn(),
				Port: int(peer.Port),
			})
		}
	}
	peerOrg.AnchorPeers = anchorPeers
	return peerOrg
}

func getOrdererOrg(org *ppb.Organization, policy *ppb.FabricPolicy) *genesisconfig.Organization {
	ordererOrg := org
	if policy == nil {
		policy = &ppb.FabricPolicy{}
	}

	// ordererEndpoints := []string{}

	// for _, orderer := range org.GetOrderers() {
	// 	ordererEndpoints = append(ordererEndpoints, orderer.GetUrl())
	// }

	ordPolicies := getOrgPolicies(ordererOrg.GetMspId(), policy.GetOrgPolicies()[org.GetMspId()])
	return &genesisconfig.Organization{
		Name:     ordererOrg.GetMspId(),
		ID:       ordererOrg.GetMspId(),
		Policies: ordPolicies,
		//OrdererEndpoints: ordererEndpoints,
	}
}

func getApplicationOrgProfile(mgr *fabric.Manager, additionalOrgs []*ppb.Organization) *genesisconfig.Profile {
	logger := logging.GetLogger()
	peerOrg := getApplicationOrg(mgr.Org, mgr.Policy)
	mapCapability := make(map[string]bool)
	mapCapability[ApplicationCapabilities] = true

	//TODO: Fix ACLS then uncomment this code
	// channel acls
	//acls := getChannelAcls(mgr.Policy.Acls)
	// policies
	applicationPolicies := getImplicitMetaPolicies(mgr.Policy.ApplicationPolicies)
	profilePolicies := getImplicitMetaPolicies(mgr.Policy.ChannelPolicies)

	organizations := []*genesisconfig.Organization{peerOrg}

	for _, org := range additionalOrgs {
		organizations = append(organizations, getApplicationOrg(org, mgr.Policy))
	}

	application := genesisconfig.Application{Organizations: organizations, Capabilities: mapCapability /*, ACLs: acls*/, Policies: applicationPolicies}
	profile := genesisconfig.Profile{Consortium: consortiumName, Application: &application, Policies: profilePolicies}

	logger.Debug("App org profile", zap.Any("profile", profile))

	return &profile
}

func getOrdererOrgProfile(mgr *fabric.Manager, orderers []*ppb.Orderer) *genesisconfig.Profile {
	// var brokers = []string{"kafka-0.broker.kafka:9092", "kafka-1.broker.kafka:9092", "kafka-2.broker.kafka:9092", "kafka-3.broker.kafka:9092"}
	//var brokers = []string{"hl-kafka-0.hl-kafka-brokers.strimzi.svc.cluster.local:9093", "hl-kafka-1.hl-kafka-brokers.strimzi.svc.cluster.local:9093", "hl-kafka-2.hl-kafka-brokers.strimzi.svc.cluster.local:9093"}
	//kafka := genesisconfig.Kafka{Brokers: brokers}
	batchsize := genesisconfig.BatchSize{MaxMessageCount: maxMessageCount, AbsoluteMaxBytes: absoluteMaxBytes, PreferredMaxBytes: preferredMaxBytes}
	ordererOrg := getOrdererOrg(mgr.Org, mgr.Policy)
	// orgPolicies := getOrgPolicies(mgr.Org.GetMspId(), mgr.Policy.OrgPolicies)
	// peerOrg := genesisconfig.Organization{Name: mgr.Org.GetMspId(), ID: mgr.Org.GetMspId(), Policies: orgPolicies} // todo: remove

	consortium := genesisconfig.Consortium{Organizations: []*genesisconfig.Organization{ordererOrg}}
	mapConsortium := make(map[string]*genesisconfig.Consortium)
	mapConsortium[consortiumName] = &consortium
	// Parametrize addressess when scale of orderers is implemented
	mapCapability := make(map[string]bool)
	mapCapability[OrdererCapabilities] = true

	mapChannelCapability := make(map[string]bool)
	mapChannelCapability[SystemChannelCapabilities] = true

	// orderer policies
	ordererPolicies := getOrdererPolicies(mgr.Policy.GetOrdererPolicies())
	profilePolicies := getImplicitMetaPolicies(mgr.Policy.GetChannelPolicies())

	consenters := []*etcdraft.Consenter{}
	addresses := []string{}

	for _, orderer := range orderers {
		c := &etcdraft.Consenter{
			Host: orderer.GetCn(),
			Port: 7050,
			//ClientTlsCert: []byte(orderer.GetTlsCas()[0].GetContent()),
			ClientTlsCert: orderer.GetClusterServerCert(),
			//ServerTlsCert: []byte(orderer.GetTlsCas()[0].GetContent()),
			ServerTlsCert: orderer.GetClusterServerCert(),
		}
		consenters = append(consenters, c)
		addresses = append(addresses, orderer.GetUrl())
	}

	etcdRaft := &etcdraft.ConfigMetadata{
		Options: &etcdraft.Options{
			ElectionTick:         10,
			HeartbeatTick:        1,
			MaxInflightBlocks:    5,
			SnapshotIntervalSize: 104857600,
			TickInterval:         "500ms",
		},
		//TODO For loop
		Consenters: consenters,
	}

	ordererConfig := &genesisconfig.Orderer{
		EtcdRaft:     etcdRaft,
		Policies:     ordererPolicies,
		Capabilities: mapCapability,
		OrdererType:  ordererType,
		Addresses:    addresses,
		BatchTimeout: batchTimeout,
		BatchSize:    batchsize,
		//Kafka:         kafka,
		Organizations: []*genesisconfig.Organization{ordererOrg},
	}

	profile := genesisconfig.Profile{
		Capabilities: mapChannelCapability,
		Consortium:   consortiumName,
		Orderer:      ordererConfig,
		Consortiums:  mapConsortium,
		Policies:     profilePolicies,
	}

	return &profile
}

// GenerateOrdererGenesisBlock ..
func GenerateOrdererGenesisBlock(mgr *fabric.Manager, orderers []*ppb.Orderer) ([]byte, error) {
	logger := logging.GetLogger()
	profileConfig := getOrdererOrgProfile(mgr, orderers)

	caCertsMap := make(map[string]*ppb.CA)
	adminCertsMap := make(map[string]*ppb.AdminCertificate)

	for _, orderer := range orderers {
		for _, admin := range orderer.GetAdminCerts() {
			adminCertsMap[admin.GetName()] = admin
		}
		for _, ca := range orderer.GetCas() {
			caCertsMap[ca.GetName()] = ca
		}
	}

	var caCerts []*ppb.CA
	var adminCerts []*ppb.AdminCertificate

	for _, cert := range caCertsMap {
		caCerts = append(caCerts, cert)
	}
	for _, cert := range adminCertsMap {
		adminCerts = append(adminCerts, cert)
	}

	certs := fabric.Certs{AdminCerts: adminCerts, CaCerts: caCerts}

	logger.Debug("Profile", zap.Any("config", profileConfig))

	if profileConfig == nil {
		return nil, errors.Errorf("%v Error getting orderer profile configuration", logging.FuncInfo())
	}
	return doOutputBlock(profileConfig, ordererSystemChannelID, &certs, mgr.Policy)
}

// GenerateChannelGenesisBlock ...
func GenerateChannelGenesisBlock(mgr *fabric.Manager, additionalOrgs []*ppb.Organization) ([]byte, error) {
	profileConfig := getApplicationOrgProfile(mgr, additionalOrgs)
	certs := fabric.Certs{AdminCerts: mgr.Org.GetAdminCerts(), CaCerts: mgr.Org.GetCas()}
	if profileConfig == nil {
		return nil, errors.Errorf("%v Error getting application org profile configuration", logging.FuncInfo())
	}
	channelID := mgr.Channel.Name

	//TODO: Change when multiple orgs are in ordsyschannel
	mspid := mgr.Org.GetId().GetValue()

	endpoints := map[string][]string{mspid: {}}
	for _, orderer := range mgr.Org.GetOrderers() {
		endpoints[mspid] = append(endpoints[mspid], orderer.GetUrl())
	}

	return doOutputChannelCreateTx(profileConfig, channelID, &certs, endpoints, mgr.Policy)
}

// GenerateAnchorPeersBlock ...
func GenerateAnchorPeersBlock(ctx context.Context, mgr *fabric.Manager) ([]byte, *cb.ConfigUpdate, error) {
	org := getApplicationOrgWithAnchors(mgr.Org, mgr.Policy, mgr.Channel.GetPeers())

	anchorPeers := make([]*pb.AnchorPeer, len(org.AnchorPeers))
	for i, anchorPeer := range org.AnchorPeers {
		anchorPeers[i] = &pb.AnchorPeer{
			Host: anchorPeer.Host,
			Port: int32(anchorPeer.Port),
		}
	}

	readset, writeset, err := mgr.GetChannelConfig(ctx)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}

	// must increment version of element that needs to be changed
	//readsetApplicationVersion := readset.Groups[channelconfig.ApplicationGroupKey].GetVersion()
	readsetApplicationGroupVersion := readset.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name].GetVersion()
	//writeset.Groups[channelconfig.ApplicationGroupKey].Version = readsetApplicationVersion + 1
	writeset.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name].Version = readsetApplicationGroupVersion + 1
	writeset.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name].Values[channelconfig.AnchorPeersKey] = &cb.ConfigValue{
		Value:     utils.MarshalOrPanic(channelconfig.AnchorPeersValue(anchorPeers).Value()),
		ModPolicy: channelconfig.AdminsPolicyKey,
	}

	return CreateConfigUpdateAndEnvelope(mgr.Channel.GetName(), readset, writeset, nil)
}

// GenerateOrgConfigBlock ...
func GenerateOrgConfigBlock(ctx context.Context, newOrg *ppb.Organization, policy *ppb.FabricPolicy, mgr *fabric.Manager, peers []*ppb.Peer) ([]byte, *cb.ConfigUpdate, error) {
	org := getApplicationOrgWithAnchors(newOrg, policy, peers)
	if org == nil {
		return nil, nil, errors.Errorf("%v Error getting application org configuration", logging.FuncInfo())
	}

	//certs := fabric.Certs{AdminCerts: newOrg.GetAdminCerts(), CaCerts: newOrg.GetCas()}
	og, err := encoder.NewOrdererOrgGroup(org)
	// fmt.Println("PRINTING OG")
	// if err := protolator.DeepMarshalJSON(os.Stdout, &cb.DynamicConsortiumOrgGroup{ConfigGroup: og}); err != nil {
	// 	err = errors.Wrapf(err, "%v json marshalling newly generated org failed", logging.FuncInfo())
	// 	return nil, nil, err
	// }

	readset, writeset, err := mgr.GetChannelConfig(ctx)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}

	// must increment version of element that needs to be changed
	readsetApplicationVersion := readset.Groups[channelconfig.ApplicationGroupKey].GetVersion()
	// check if the mspid is already present in channel
	if _, notOk := readset.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name]; notOk {
		return nil, nil, errors.Errorf("%v Error generating config_update, channel %v already contains organization with MspID %v", logging.FuncInfo(), mgr.Channel.GetName(), org.Name)
	}
	writeset.Groups[channelconfig.ApplicationGroupKey].Version = readsetApplicationVersion + 1
	writeset.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name] = og

	if len(org.AnchorPeers) > 0 {
		anchorPeers := make([]*pb.AnchorPeer, len(org.AnchorPeers))
		for i, anchorPeer := range org.AnchorPeers {
			anchorPeers[i] = &pb.AnchorPeer{
				Host: anchorPeer.Host,
				Port: int32(anchorPeer.Port),
			}
		}

		writeset.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name].Values[channelconfig.AnchorPeersKey] = &cb.ConfigValue{
			Value:     utils.MarshalOrPanic(channelconfig.AnchorPeersValue(anchorPeers).Value()),
			ModPolicy: channelconfig.AdminsPolicyKey,
		}
	}

	return CreateConfigUpdateAndEnvelope(mgr.Channel.GetName(), readset, writeset, nil)
}

func addOrdererAddresses(addresses []string, readset, writeset *cb.ConfigGroup) (*cb.ConfigGroup, *cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	urls := &cb.OrdererAddresses{}
	err := proto.Unmarshal(readset.Values[channelconfig.OrdererAddressesKey].GetValue(), urls)
	if err != nil {
		err = errors.Wrapf(err, "%v json unmarshalling of readset failed", logging.FuncInfo())
		return nil, nil, err
	}
	for _, addr := range addresses {
		urls.Addresses = append(urls.Addresses, strings.TrimSpace(addr))
	}

	logger.Debug("Orderer addresses", zap.Any("URLs", urls.GetAddresses()))
	chConf1 := channelconfig.OrdererAddressesValue(urls.Addresses)

	// must increment version of element that needs to be changed
	readsetOrdererVersion := readset.Values[channelconfig.OrdererAddressesKey].GetVersion()
	writeset.Values[channelconfig.OrdererAddressesKey].Version = readsetOrdererVersion + 1
	writeset.Values[channelconfig.OrdererAddressesKey].Value = utils.MarshalOrPanic(chConf1.Value())

	return readset, writeset, nil
}

func addOrgOrdererAddresses(addresses []string, mspid string, readset, writeset *cb.ConfigGroup) (*cb.ConfigGroup, *cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	urls := &cb.OrdererAddresses{}
	var version uint64

	logger.Debug("New endpoints", zap.Any("URLs", addresses))

	err := proto.Unmarshal(readset.Groups[channelconfig.OrdererGroupKey].Groups[mspid].GetValues()[channelconfig.EndpointsKey].GetValue(), urls)
	if err != nil {
		err = errors.Wrapf(err, "%v json unmarshalling of endpoints failed", logging.FuncInfo())
		return nil, nil, err
	}

	logger.Debug("Current endpoints", zap.Any("URLs", urls.GetAddresses()))

	for _, addr := range addresses {
		found := false
		for _, uAddr := range urls.Addresses {
			if uAddr == addr {
				found = true
				break
			}
		}
		if !found {
			urls.Addresses = append(urls.Addresses, strings.TrimSpace(addr))
		}
	}

	ordererEndpointsVal := channelconfig.EndpointsValue(urls.Addresses)
	ordererEndpointsValBytes, _ := proto.Marshal(ordererEndpointsVal.Value())

	currentEndpoints, ok := readset.GetGroups()[channelconfig.OrdererGroupKey].GetGroups()[mspid].GetValues()[channelconfig.EndpointsKey]

	if ok {
		version = currentEndpoints.GetVersion() + 1
	}

	endpoints := &cb.ConfigValue{Version: version, Value: ordererEndpointsValBytes, ModPolicy: "Admins"}

	writeset.Groups[channelconfig.OrdererGroupKey].Groups[mspid].Values[channelconfig.EndpointsKey] = endpoints

	return readset, writeset, nil
}

func addEtcdraftOrderers(orderers []*ppb.Orderer, readset, writeset *cb.ConfigGroup) (*cb.ConfigGroup, *cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	consensusType := &ob.ConsensusType{}
	err := proto.Unmarshal(readset.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].GetValue(), consensusType)
	if err != nil {
		err = errors.Wrapf(err, "%v json unmarshalling of readset failed", logging.FuncInfo())
		return nil, nil, err
	}
	metadata := &etcdraft.ConfigMetadata{}
	err = proto.Unmarshal(consensusType.Metadata, metadata)
	if err != nil {
		err = errors.Wrapf(err, "%v json unmarshalling of readset failed", logging.FuncInfo())
		return nil, nil, err
	}

	//TODO iterate for remove duplicity
	//TODO iterate to update current object certs
	consenters := metadata.GetConsenters()

	//Build update object with consenters
	for _, orderer := range orderers {
		consenter := &etcdraft.Consenter{
			Host: orderer.GetCn(),
			Port: 7050,
			//ClientTlsCert: []byte(orderer.GetTlsCas()[0].GetContent()),
			ClientTlsCert: orderer.GetClusterServerCert(),
			//ServerTlsCert: []byte(orderer.GetTlsCas()[0].GetContent()),
			ServerTlsCert: orderer.GetClusterServerCert(),
		}
		consenters = append(consenters, consenter)
	}

	logger.Debug("ConsensusType metadata", zap.Any("Consenters", consenters))

	metadata.Consenters = consenters
	metadataBytes, err := proto.Marshal(metadata)
	if err != nil {
		err = errors.Wrapf(err, "%v json marshalling of metadata failed", logging.FuncInfo())
		return nil, nil, err
	}
	chConf1 := channelconfig.ConsensusTypeValue("etcdraft", metadataBytes)

	// must increment version of element that needs to be changed
	readsetOrdererVersion := readset.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].GetVersion()
	writeset.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Version = readsetOrdererVersion + 1
	writeset.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value = utils.MarshalOrPanic(chConf1.Value())

	return readset, writeset, nil
}

// CreateConfigUpdateEnvelope marshals readset and writeset into proto.ConfigUpdate
func CreateConfigUpdateEnvelope(channelID string, configUpdateBytes []byte, signatures []*cb.ConfigSignature) ([]byte, error) {
	// configupdate tady uz musi byt delta, tj ten spravny channel_id, readset a writeset
	// configtxlator compute_update --channel_id $CHANNEL_NAME --original config.pb --updated modified_config.pb --output org3_update.pb
	configUpdateEnvelope := &cb.ConfigUpdateEnvelope{ // configUpdateEnvelope = configtxlator proto_decode --input org3_update.pb --type common.ConfigUpdate | jq . > org3_update.json
		ConfigUpdate: configUpdateBytes,
		Signatures:   signatures,
	}

	configUpdateEnvelopeBytes, err := utils.Marshal(configUpdateEnvelope)
	if err != nil {
		return nil, errors.Errorf("%v marshalling ConfigUpdateEnvelope failed", logging.FuncInfo())
	}

	channelHeaderBytes, err := utils.Marshal(&cb.ChannelHeader{ChannelId: channelID, Type: int32(cb.HeaderType_CONFIG_UPDATE)})
	if err != nil {
		return nil, errors.Errorf("%v marshalling ChannelHeader failed", logging.FuncInfo())
	}

	payloadBytes, err := utils.Marshal(&cb.Payload{Header: &cb.Header{ChannelHeader: channelHeaderBytes}, Data: configUpdateEnvelopeBytes})
	if err != nil {
		return nil, errors.Errorf("%v marshalling Payload failed", logging.FuncInfo())
	}

	// configtxlator proto_encode --input org3_update_in_envelope.json --type common.Envelope --output org3_update_in_envelope.pb // sem by se meli pridavat postupne i signatures
	// echo '{"payload":{"header":{"channel_header":{"channel_id":"mychannel", "type":2}},"data":{"config_update":'$(cat org3_update.json)'}}}' | jq . > org3_update_in_envelope.json
	envelope := &cb.Envelope{Payload: payloadBytes}

	// fmt.Println("envelope")
	// if err := protolator.DeepMarshalJSON(os.Stdout, envelope); err != nil {
	// 	err = errors.Wrapf(err, "%v json marshalling envelope failed", logging.FuncInfo())
	// 	return nil, nil, err
	// }

	envelopeBytes, err := utils.Marshal(envelope) // org3_update_in_envelope.pb
	if err != nil {
		return nil, errors.Errorf("%v Error marshaling add org to channel update", logging.FuncInfo())
	}

	return envelopeBytes, nil
}

// CreateConfigUpdate marshals wraps common.ConfigUpdate into common.ConfigUpdate
func CreateConfigUpdate(channelID string, readset, writeset *cb.ConfigGroup) (*cb.ConfigUpdate, []byte, error) {
	configUpdate := &cb.ConfigUpdate{
		ChannelId: channelID,
		ReadSet:   readset,
		WriteSet:  writeset,
	}

	configUpdateBytes, err := utils.Marshal(configUpdate)
	if err != nil {
		return nil, nil, errors.Errorf("%v marshalling ConfigUpdate failed", logging.FuncInfo())
	}

	return configUpdate, configUpdateBytes, nil
}

// CreateConfigUpdateAndEnvelope ...
func CreateConfigUpdateAndEnvelope(channelID string, readset, writeset *cb.ConfigGroup, signatures []*cb.ConfigSignature) ([]byte, *cb.ConfigUpdate, error) {
	configUpdate, configUpdateBytes, err := CreateConfigUpdate(channelID, readset, writeset)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}

	configUpdateEnvelope, err := CreateConfigUpdateEnvelope(channelID, configUpdateBytes, signatures)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}

	return configUpdateEnvelope, configUpdate, nil
}

// UnmarshalEnvelope ...
func UnmarshalEnvelope(cUpdate []byte) (*cb.ConfigUpdate, error) {
	testEnvelope, err := utils.UnmarshalEnvelope(cUpdate) // cb.Envelope
	if err != nil {
		return nil, errors.Errorf("%v Error unmarshaling cb.Envelope", logging.FuncInfo())
	}
	configUpdateEnvelope, err := utils.EnvelopeToConfigUpdate(testEnvelope) // cb.ConfigUpdateEnvelope
	if err != nil {
		return nil, errors.Errorf("%v Error unmarshaling cb.ConfigUpdateEnvelope", logging.FuncInfo())
	}
	// fmt.Println("configUpdateEnvelope-unmarshal")
	// if err := protolator.DeepMarshalJSON(os.Stdout, configUpdateEnvelope); err != nil {
	// 	err = errors.Wrapf(err, "%v json marshalling configUpdateEnvelope failed", logging.FuncInfo())
	// 	return nil, err
	// }
	confUpdate := &cb.ConfigUpdate{}
	err = proto.Unmarshal(configUpdateEnvelope.ConfigUpdate, confUpdate)
	if err != nil {
		return nil, errors.Errorf("%v Error unmarshaling cb.ConfigUpdate", logging.FuncInfo())
	}
	// fmt.Println("configupdate-unmarshal")
	// if err := protolator.DeepMarshalJSON(os.Stdout, confUpdate); err != nil {
	// 	err = errors.Wrapf(err, "%v json marshalling configUpdate failed", logging.FuncInfo())
	// 	return nil, err
	// }
	return confUpdate, nil
}

// GenerateAddOrdererOrgConfigBlock ...
func GenerateAddOrdererOrgConfigBlock(ctx context.Context, mgr *fabric.Manager, addresses []string) ([]byte, *cb.ConfigUpdate, error) {
	org := getOrdererOrg(mgr.Org, mgr.Policy)
	if org == nil {
		return nil, nil, errors.Errorf("%v Error getting application org configuration", logging.FuncInfo())
	}
	//certs := fabric.Certs{AdminCerts: mgr.Org.GetAdminCerts(), CaCerts: mgr.Org.GetCas()}
	og, err := encoder.NewOrdererOrgGroup(org)
	//og, err := encoder.NewOrdererOrgGroup(org)
	// fmt.Println("PRINTING OG")
	// if err := protolator.DeepMarshalJSON(os.Stdout, &cb.DynamicConsortiumOrgGroup{ConfigGroup: og}); err != nil {
	// 	err = errors.Wrapf(err, "%v json marshalling newly generated orderer org failed", logging.FuncInfo())
	// 	return nil, nil, err
	// }

	readset, writeset, err := mgr.GetChannelConfig(ctx)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}

	// must increment version of element that needs to be changed
	readsetOrdererVersion := readset.Groups[channelconfig.OrdererGroupKey].GetVersion()
	// check if the mspid is already present in channel
	if _, notOk := readset.Groups[channelconfig.OrdererGroupKey].Groups[org.Name]; notOk {
		return nil, nil, errors.Errorf("%v Error generating config_update, channel %v already contains orderer organization with MspID %v", logging.FuncInfo(), mgr.Channel.GetName(), org.Name)
	}
	writeset.Groups[channelconfig.OrdererGroupKey].Version = readsetOrdererVersion + 1
	writeset.Groups[channelconfig.OrdererGroupKey].Groups[org.Name] = og

	if len(addresses) > 0 {
		readset, writeset, err = addOrdererAddresses(addresses, readset, writeset)
		if err != nil {
			err = errors.Wrapf(err, "%v adding orderer addresses to the config writeset failed", logging.FuncInfo())
			return nil, nil, err
		}
	}
	return CreateConfigUpdateAndEnvelope(mgr.Channel.GetName(), readset, writeset, nil)
}

// GenerateAddOrdererAddressessConfigBlock ...
func GenerateAddOrdererAddressessConfigBlock(ctx context.Context, addresses []string, mgr *fabric.Manager) ([]byte, *cb.ConfigUpdate, error) {
	readset, writeset, err := mgr.GetChannelConfig(ctx)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}
	readset, writeset, err = addOrgOrdererAddresses(addresses, mgr.Org.GetId().GetValue(), readset, writeset)
	if err != nil {
		err = errors.Wrapf(err, "%v adding orderer addresses to the config writeset failed", logging.FuncInfo())
		return nil, nil, err
	}

	return CreateConfigUpdateAndEnvelope(mgr.Channel.GetName(), readset, writeset, nil)
}

// GenerateAddOrdererSystemConfigBlock ...
func GenerateAddOrdererSystemConfigBlock(ctx context.Context, mgr *fabric.Manager, orderers []*ppb.Orderer) ([]byte, *cb.ConfigUpdate, error) {
	readset, writeset, err := mgr.GetChannelConfig(ctx)
	if err != nil {
		err = errors.Wrapf(err, "%v getting channel config failed", logging.FuncInfo())
		return nil, nil, err
	}

	addresses := []string{}
	for _, orderer := range orderers {
		addresses = append(addresses, orderer.GetCn())
	}

	readset, writeset, err = addEtcdraftOrderers(orderers, readset, writeset)
	if err != nil {
		err = errors.Wrapf(err, "%v adding orderer consenters to the config writeset failed", logging.FuncInfo())
		return nil, nil, err
	}

	readset, writeset, err = addOrdererAddresses(addresses, readset, writeset)
	if err != nil {
		err = errors.Wrapf(err, "%v adding orderer addresses to the config writeset failed", logging.FuncInfo())
		return nil, nil, err
	}

	return CreateConfigUpdateAndEnvelope(mgr.Channel.GetName(), readset, writeset, nil)
}
