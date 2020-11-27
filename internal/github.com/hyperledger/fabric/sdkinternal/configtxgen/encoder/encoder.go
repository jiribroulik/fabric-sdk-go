/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package encoder

import (
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/genesis"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/policies"
	cauthdsl "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/policydsl"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/msp"
	utils "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/genesisconfig"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxlator/update"
	//"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/pkg/identity"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	//"github.com/op/go-logging"
	"github.com/pkg/errors"
	"github.com/KompiTech/go-toolkit/logging"
	"github.com/KompiTech/manblock-fabric-orchestrator/pkg/fabric"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"

)

const (
	ordererAdminsPolicyName = "/Channel/Orderer/Admins"

	msgVersion = int32(0)
	epoch      = 0
)

var logger = flogging.MustGetLogger("common.tools.configtxgen.encoder")

const (
	// ConsensusTypeSolo identifies the solo consensus implementation.
	ConsensusTypeSolo = "solo"
	// ConsensusTypeKafka identifies the Kafka-based consensus implementation.
	ConsensusTypeKafka = "kafka"
	// ConsensusTypeKafka identifies the Kafka-based consensus implementation.
	ConsensusTypeEtcdRaft = "etcdraft"

	// BlockValidationPolicyKey TODO
	BlockValidationPolicyKey = "BlockValidation"

	// OrdererAdminsPolicy is the absolute path to the orderer admins policy
	OrdererAdminsPolicy = "/Channel/Orderer/Admins"

	// SignaturePolicyType is the 'Type' string for signature policies
	SignaturePolicyType = "Signature"

	// ImplicitMetaPolicyType is the 'Type' string for implicit meta policies
	ImplicitMetaPolicyType = "ImplicitMeta"
)

func addValue(cg *cb.ConfigGroup, value channelconfig.ConfigValue, modPolicy string) {
	cg.Values[value.Key()] = &cb.ConfigValue{
		Value:     utils.MarshalOrPanic(value.Value()),
		ModPolicy: modPolicy,
	}
}

func addPolicy(cg *cb.ConfigGroup, policy policies.ConfigPolicy, modPolicy string) {
	cg.Policies[policy.Key()] = &cb.ConfigPolicy{
		Policy:    policy.Value(),
		ModPolicy: modPolicy,
	}
}

func addPolicies(cg *cb.ConfigGroup, policyMap map[string]*genesisconfig.Policy, modPolicy string) error {
	for policyName, policy := range policyMap {
		switch policy.Type {
		case ImplicitMetaPolicyType:
			imp, err := policies.ImplicitMetaFromString(policy.Rule)
			if err != nil {
				err = errors.Wrapf(err, "%v invalid implicit meta policy rule '%s'", logging.FuncInfo(), policy.Rule)
				return err
			}
			cg.Policies[policyName] = &cb.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &cb.Policy{
					Type:  int32(cb.Policy_IMPLICIT_META),
					Value: utils.MarshalOrPanic(imp),
				},
			}
		case SignaturePolicyType:
			sp, err := cauthdsl.FromString(policy.Rule)
			if err != nil {
				err = errors.Wrapf(err, "%v invalid signature policy rule '%s'", logging.FuncInfo(), policy.Rule)
				return err
			}
			cg.Policies[policyName] = &cb.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &cb.Policy{
					Type:  int32(cb.Policy_SIGNATURE),
					Value: utils.MarshalOrPanic(sp),
				},
			}
		default:
			return errors.Errorf("%v unknown policy type: %s", logging.FuncInfo(), policy.Type)
		}
	}
	return nil
}

// addImplicitMetaPolicyDefaults adds the Readers/Writers/Admins policies, with Any/Any/Majority rules respectively.
func addImplicitMetaPolicyDefaults(cg *cb.ConfigGroup) {
	addPolicy(cg, policies.ImplicitMetaMajorityPolicy(channelconfig.AdminsPolicyKey), channelconfig.AdminsPolicyKey)
	addPolicy(cg, policies.ImplicitMetaAnyPolicy(channelconfig.ReadersPolicyKey), channelconfig.AdminsPolicyKey)
	addPolicy(cg, policies.ImplicitMetaAnyPolicy(channelconfig.WritersPolicyKey), channelconfig.AdminsPolicyKey)
}

// addSignaturePolicyDefaults adds the Readers/Writers/Admins policies as signature policies requiring one signature from the given mspID.
// If devMode is set to true, the Admins policy will accept arbitrary user certs for admin functions, otherwise it requires the cert satisfies
// the admin role principal.
func addSignaturePolicyDefaults(cg *cb.ConfigGroup, mspID string, devMode bool) {
	logger := logging.GetLogger()
	if devMode {
		logger.Warn("Specifying AdminPrincipal is deprecated and will be removed in a future release, override the admin principal with explicit policies.")
		addPolicy(cg, policies.SignaturePolicy(channelconfig.AdminsPolicyKey, cauthdsl.SignedByMspMember(mspID)), channelconfig.AdminsPolicyKey)
	} else {
		addPolicy(cg, policies.SignaturePolicy(channelconfig.AdminsPolicyKey, cauthdsl.SignedByMspAdmin(mspID)), channelconfig.AdminsPolicyKey)
	}
	addPolicy(cg, policies.SignaturePolicy(channelconfig.ReadersPolicyKey, cauthdsl.SignedByMspMember(mspID)), channelconfig.AdminsPolicyKey)
	addPolicy(cg, policies.SignaturePolicy(channelconfig.WritersPolicyKey, cauthdsl.SignedByMspMember(mspID)), channelconfig.AdminsPolicyKey)
}

// NewChannelGroup defines the root of the channel configuration.  It defines basic operating principles like the hashing
// algorithm used for the blocks, as well as the location of the ordering service.  It will recursively call into the
// NewOrdererGroup, NewConsortiumsGroup, and NewApplicationGroup depending on whether these sub-elements are set in the
// configuration.  All mod_policy values are set to "Admins" for this group, with the exception of the OrdererAddresses
// value which is set to "/Channel/Orderer/Admins".
func NewChannelGroup(conf *genesisconfig.Profile, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	if conf.Orderer == nil {
		return nil, errors.Errorf("%v missing orderer config section", logging.FuncInfo())
	}

	channelGroup := cb.NewConfigGroup()
	if len(conf.Policies) == 0 {
		logger.Warn("Default policy emission is deprecated, please include policy specificiations for the channel group in configtx.yaml")
		addImplicitMetaPolicyDefaults(channelGroup)
	} else {
		if err := addPolicies(channelGroup, conf.Policies, channelconfig.AdminsPolicyKey); err != nil {
			err = errors.Wrapf(err, "%v adding policies to channel group failed", logging.FuncInfo())
			return nil, err
		}
	}

	addValue(channelGroup, channelconfig.HashingAlgorithmValue(), channelconfig.AdminsPolicyKey)
	addValue(channelGroup, channelconfig.BlockDataHashingStructureValue(), channelconfig.AdminsPolicyKey)
	addValue(channelGroup, channelconfig.OrdererAddressesValue(conf.Orderer.Addresses), ordererAdminsPolicyName)

	if conf.Consortium != "" {
		addValue(channelGroup, channelconfig.ConsortiumValue(conf.Consortium), channelconfig.AdminsPolicyKey)
	}

	if len(conf.Capabilities) > 0 {
		addValue(channelGroup, channelconfig.CapabilitiesValue(conf.Capabilities), channelconfig.AdminsPolicyKey)
	}

	var err error
	channelGroup.Groups[channelconfig.OrdererGroupKey], err = NewOrdererGroup(conf.Orderer, certs, policy)
	if err != nil {
		err = errors.Wrapf(err, "%v could not create orderer group", logging.FuncInfo())
		return nil, err
	}

	if conf.Application != nil {
		channelGroup.Groups[channelconfig.ApplicationGroupKey], err = NewApplicationGroup(conf.Application, certs, policy)
		if err != nil {
			err = errors.Wrapf(err, "%v could not create application group", logging.FuncInfo())
			return nil, err
		}
	}

	if conf.Consortiums != nil {
		channelGroup.Groups[channelconfig.ConsortiumsGroupKey], err = NewConsortiumsGroup(conf.Consortiums, certs, policy)
		if err != nil {
			err = errors.Wrapf(err, "%v could not create consortiums group", logging.FuncInfo())
			return nil, err
		}
	}

	if policy.GetChannelModPolicy() == "" {
		channelGroup.ModPolicy = channelconfig.AdminsPolicyKey
	} else {
		channelGroup.ModPolicy = policy.GetChannelModPolicy()
	}
	return channelGroup, nil
}

// NewOrdererGroup returns the orderer component of the channel configuration.  It defines parameters of the ordering service
// about how large blocks should be, how frequently they should be emitted, etc. as well as the organizations of the ordering network.
// It sets the mod_policy of all elements to "Admins".  This group is always present in any channel configuration.
func NewOrdererGroup(conf *genesisconfig.Orderer, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	ordererGroup := cb.NewConfigGroup()
	if len(conf.Policies) == 0 {
		logger.Warn("Default policy emission is deprecated, please include policy specifications for the orderer group in configtx.yaml")
		addImplicitMetaPolicyDefaults(ordererGroup)
	} else {
		if err := addPolicies(ordererGroup, conf.Policies, channelconfig.AdminsPolicyKey); err != nil {
			return nil, errors.Wrapf(err, "error adding policies to orderer group")
		}
	}
	ordererGroup.Policies[BlockValidationPolicyKey] = &cb.ConfigPolicy{
		Policy:    policies.ImplicitMetaAnyPolicy(channelconfig.WritersPolicyKey).Value(),
		ModPolicy: channelconfig.AdminsPolicyKey,
	}
	addValue(ordererGroup, channelconfig.BatchSizeValue(
		conf.BatchSize.MaxMessageCount,
		conf.BatchSize.AbsoluteMaxBytes,
		conf.BatchSize.PreferredMaxBytes,
	), channelconfig.AdminsPolicyKey)
	addValue(ordererGroup, channelconfig.BatchTimeoutValue(conf.BatchTimeout.String()), channelconfig.AdminsPolicyKey)
	addValue(ordererGroup, channelconfig.ChannelRestrictionsValue(conf.MaxChannels), channelconfig.AdminsPolicyKey)

	if len(conf.Capabilities) > 0 {
		addValue(ordererGroup, channelconfig.CapabilitiesValue(conf.Capabilities), channelconfig.AdminsPolicyKey)
	}

	var consensusMetadata []byte
	var err error

	switch conf.OrdererType {
	case ConsensusTypeSolo:
	case ConsensusTypeKafka:
		addValue(ordererGroup, channelconfig.KafkaBrokersValue(conf.Kafka.Brokers), channelconfig.AdminsPolicyKey)
	case etcdraft.TypeKey:
		if consensusMetadata, err = proto.Marshal(conf.EtcdRaft); err != nil {
			err = errors.Wrapf(err, "%v cannot marshal metadata for orderer type %s", logging.FuncInfo(), etcdraft.TypeKey)
			return nil, err
		}
	default:
		return nil, errors.Errorf("%v unknown orderer type: %s", logging.FuncInfo(), conf.OrdererType)
	}

	addValue(ordererGroup, channelconfig.ConsensusTypeValue(conf.OrdererType, consensusMetadata), channelconfig.AdminsPolicyKey)

	for _, org := range conf.Organizations {
		var err error
		ordererGroup.Groups[org.Name], err = NewOrdererOrgGroup(org, certs, policy)
		if err != nil {
			err = errors.Wrapf(err, "%v creating orderer org failed", logging.FuncInfo())
			return nil, err
		}
	}

	if policy.GetOrdererModPolicy() == "" {
		ordererGroup.ModPolicy = channelconfig.AdminsPolicyKey
	} else {
		ordererGroup.ModPolicy = policy.GetOrdererModPolicy()
	}
	return ordererGroup, nil
}

// NewOrdererOrgGroup returns an orderer org component of the channel configuration.  It defines the crypto material for the
// organization (its MSP).  It sets the mod_policy of all elements to "Admins".
func NewOrdererOrgGroup(conf *genesisconfig.Organization, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	mspConfig, err := msp.GetVerifyingMspConfig(conf.MSPDir, conf.ID, conf.MSPType, certs)
	if err != nil {
		err = errors.Wrapf(err, "%v loading MSP configuration for org: %s failed", logging.FuncInfo(), conf.Name)
		return nil, err
	}

	ordererOrgGroup := cb.NewConfigGroup()

	if len(conf.Policies) == 0 {
		logger.Warn("Default policy emission is deprecated, please include policy specificiations for the orderer org group in configtx.yaml", zap.String("orderer org group", conf.Name))
		addSignaturePolicyDefaults(ordererOrgGroup, conf.ID, conf.AdminPrincipal != genesisconfig.AdminRoleAdminPrincipal)
	} else {
		if err := addPolicies(ordererOrgGroup, conf.Policies, channelconfig.AdminsPolicyKey); err != nil {
			err = errors.Wrapf(err, "%v adding policies to orderer org group '%s' failed", logging.FuncInfo(), conf.Name)
			return nil, err
		}
	}

	addValue(ordererOrgGroup, channelconfig.MSPValue(mspConfig), channelconfig.AdminsPolicyKey)

	ordererOrgGroup.ModPolicy = channelconfig.AdminsPolicyKey

	if policy.GetOrdererOrgPolicies() != nil {
		orgPolicies, ok := policy.GetOrdererOrgPolicies()[conf.ID]

		if ok && orgPolicies.GetOrgModPolicy() != "" {
			ordererOrgGroup.ModPolicy = orgPolicies.GetOrgModPolicy()
		}
	}

	if len(conf.OrdererEndpoints) > 0 {
		addValue(ordererOrgGroup, channelconfig.EndpointsValue(conf.OrdererEndpoints), channelconfig.AdminsPolicyKey)
	}

	return ordererOrgGroup, nil
}

// NewApplicationGroup returns the application component of the channel configuration.  It defines the organizations which are involved
// in application logic like chaincodes, and how these members may interact with the orderer.  It sets the mod_policy of all elements to "Admins".
func NewApplicationGroup(conf *genesisconfig.Application, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	applicationGroup := cb.NewConfigGroup()

	if len(conf.Policies) == 0 {
		logger.Warn("Default policy emission is deprecated, please include policy specificiations for the application group in configtx.yaml")
		addImplicitMetaPolicyDefaults(applicationGroup)
	} else {
		if err := addPolicies(applicationGroup, conf.Policies, channelconfig.AdminsPolicyKey); err != nil {
			err = errors.Wrapf(err, "%v adding policies to application group failed", logging.FuncInfo())
			return nil, err
		}
	}

	if len(conf.ACLs) > 0 {
		addValue(applicationGroup, channelconfig.ACLValues(conf.ACLs), channelconfig.AdminsPolicyKey)
	}

	if len(conf.Capabilities) > 0 {
		addValue(applicationGroup, channelconfig.CapabilitiesValue(conf.Capabilities), channelconfig.AdminsPolicyKey)
	}

	for _, org := range conf.Organizations {
		var err error
		applicationGroup.Groups[org.Name], err = NewApplicationOrgGroup(org, certs, policy)
		if err != nil {
			err = errors.Wrapf(err, "%v creating application org fialed", logging.FuncInfo())
			return nil, err
		}
	}

	if policy.GetApplicationModPolicy() == "" {
		applicationGroup.ModPolicy = channelconfig.AdminsPolicyKey
	} else {
		applicationGroup.ModPolicy = policy.GetApplicationModPolicy()
	}

	return applicationGroup, nil
}

// NewApplicationOrgGroup returns an application org component of the channel configuration.  It defines the crypto material for the organization
// (its MSP) as well as its anchor peers for use by the gossip network. It sets the mod_policy of all elements to "Admins".
func NewApplicationOrgGroup(conf *genesisconfig.Organization, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	logger := logging.GetLogger()
	mspConfig, err := msp.GetVerifyingMspConfig(conf.MSPDir, conf.ID, conf.MSPType, certs)
	if err != nil {
		err = errors.Wrapf(err, "%v loading MSP configuration for org %s failed", logging.FuncInfo(), conf.Name)
		return nil, err
	}

	applicationOrgGroup := cb.NewConfigGroup()

	if len(conf.Policies) == 0 {
		logger.Warn("Default policy emission is deprecated, please include policy specificiations for the application org group in configtx.yaml", zap.String("application org group", conf.Name))
		addSignaturePolicyDefaults(applicationOrgGroup, conf.ID, conf.AdminPrincipal != genesisconfig.AdminRoleAdminPrincipal)
	} else {
		if err := addPolicies(applicationOrgGroup, conf.Policies, channelconfig.AdminsPolicyKey); err != nil {
			err = errors.Wrapf(err, "%v adding policies to application org group %s failed", logging.FuncInfo(), conf.Name)
			return nil, err
		}
	}
	addValue(applicationOrgGroup, channelconfig.MSPValue(mspConfig), channelconfig.AdminsPolicyKey)
	if len(conf.AnchorPeers) > 0 {
		var anchorProtos []*pb.AnchorPeer
		for _, anchorPeer := range conf.AnchorPeers {
			anchorProtos = append(anchorProtos, &pb.AnchorPeer{
				Host: anchorPeer.Host,
				Port: int32(anchorPeer.Port),
			})
		}
		addValue(applicationOrgGroup, channelconfig.AnchorPeersValue(anchorProtos), channelconfig.AdminsPolicyKey)
	}

	applicationOrgGroup.ModPolicy = channelconfig.AdminsPolicyKey

	if policy.GetOrgPolicies() != nil {
		orgPolicies, ok := policy.GetOrgPolicies()[conf.ID]

		if ok && orgPolicies.GetOrgModPolicy() != "" {
			applicationOrgGroup.ModPolicy = orgPolicies.GetOrgModPolicy()
		}
	}

	return applicationOrgGroup, nil
}

// NewConsortiumsGroup returns the consortiums component of the channel configuration.  This element is only defined for the ordering system channel.
// It sets the mod_policy for all elements to "/Channel/Orderer/Admins".
func NewConsortiumsGroup(conf map[string]*genesisconfig.Consortium, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	consortiumsGroup := cb.NewConfigGroup()
	// This policy is not referenced anywhere, it is only used as part of the implicit meta policy rule at the channel level, so this setting
	// effectively degrades control of the ordering system channel to the ordering admins
	addPolicy(consortiumsGroup, policies.SignaturePolicy(channelconfig.AdminsPolicyKey, cauthdsl.AcceptAllPolicy), ordererAdminsPolicyName)

	for consortiumName, consortium := range conf {
		var err error
		consortiumsGroup.Groups[consortiumName], err = NewConsortiumGroup(consortium, certs, policy)
		if err != nil {
			err = errors.Wrapf(err, "%v failed to create consortium %s", logging.FuncInfo(), consortiumName)
			return nil, err
		}
	}

	consortiumsGroup.ModPolicy = ordererAdminsPolicyName
	return consortiumsGroup, nil
}

// NewConsortiumGroup returns a consortiums component of the channel configuration.  Each consortium defines the organizations which may be involved in channel
// creation, as well as the channel creation policy the orderer checks at channel creation time to authorize the action.  It sets the mod_policy of all
// elements to "/Channel/Orderer/Admins".
func NewConsortiumGroup(conf *genesisconfig.Consortium, certs *fabric.Certs, policy *ppb.FabricPolicy) (*cb.ConfigGroup, error) {
	consortiumGroup := cb.NewConfigGroup()

	for _, org := range conf.Organizations {
		var err error
		// Note, NewOrdererOrgGroup is correct here, as the structure is identical
		consortiumGroup.Groups[org.Name], err = NewOrdererOrgGroup(org, certs, policy)
		if err != nil {
			err = errors.Wrapf(err, "%v creating consortium org failed", logging.FuncInfo())
			return nil, err
		}
	}

	addValue(consortiumGroup, channelconfig.ChannelCreationPolicyValue(policies.ImplicitMetaAnyPolicy(channelconfig.AdminsPolicyKey).Value()), ordererAdminsPolicyName)

	consortiumGroup.ModPolicy = ordererAdminsPolicyName
	return consortiumGroup, nil
}

// NewChannelCreateConfigUpdate generates a ConfigUpdate which can be sent to the orderer to create a new channel.  Optionally, the channel group of the
// ordering system channel may be passed in, and the resulting ConfigUpdate will extract the appropriate versions from this file.
func NewChannelCreateConfigUpdate(channelID string, orderingSystemChannelGroup *cb.ConfigGroup, profile *genesisconfig.Profile, certs *fabric.Certs, ordererEndpoints map[string][]string, policy *ppb.FabricPolicy) (*cb.ConfigUpdate, error) {
	if profile.Application == nil {
		return nil, errors.Errorf("%v cannot define a new channel with no Application section", logging.FuncInfo())
	}

	if profile.Consortium == "" {
		return nil, errors.Errorf("%v cannot define a new channel with no Consortium value", logging.FuncInfo())
	}

	// Otherwise, parse only the application section, and encapsulate it inside a channel group
	ag, err := NewApplicationGroup(profile.Application, certs, policy)
	if err != nil {
		err = errors.Wrapf(err, "%v could not turn channel application profile into application group", logging.FuncInfo())
		return nil, err
	}

	var template, newChannelGroup *cb.ConfigGroup

	if orderingSystemChannelGroup != nil {
		// In the case that a ordering system channel definition was provided, use it to compute the update
		if orderingSystemChannelGroup.Groups == nil {
			return nil, errors.Errorf("%v missing all channel groups", logging.FuncInfo())
		}

		consortiums, ok := orderingSystemChannelGroup.Groups[channelconfig.ConsortiumsGroupKey]
		if !ok {
			return nil, errors.Errorf("%v bad consortiums group", logging.FuncInfo())
		}

		consortium, ok := consortiums.Groups[profile.Consortium]
		if !ok {
			return nil, errors.Errorf("%v bad consortium: %s", logging.FuncInfo(), profile.Consortium)
		}

		template = proto.Clone(orderingSystemChannelGroup).(*cb.ConfigGroup)
		template.Groups[channelconfig.ApplicationGroupKey] = proto.Clone(consortium).(*cb.ConfigGroup)
		// This is a bit of a hack. If the channel config specifies all consortium members, then it does not look
		// like a modification.  The below adds a fake org with an illegal name which cannot actually exist, which
		// will always appear to be deleted, triggering the correct update computation.
		template.Groups[channelconfig.ApplicationGroupKey].Groups["*IllegalKey*!"] = &cb.ConfigGroup{}
		delete(template.Groups, channelconfig.ConsortiumsGroupKey)

		newChannelGroup = proto.Clone(orderingSystemChannelGroup).(*cb.ConfigGroup)
		delete(newChannelGroup.Groups, channelconfig.ConsortiumsGroupKey)
		newChannelGroup.Groups[channelconfig.ApplicationGroupKey].Values = ag.Values
		newChannelGroup.Groups[channelconfig.ApplicationGroupKey].Policies = ag.Policies

		for orgName, org := range template.Groups[channelconfig.ApplicationGroupKey].Groups {
			if _, ok := ag.Groups[orgName]; ok {
				newChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[orgName] = org
			}
		}
	} else {
		newChannelGroup = &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				channelconfig.ApplicationGroupKey: ag,
			},
		}

		// Otherwise assume the orgs have not been modified
		template = proto.Clone(newChannelGroup).(*cb.ConfigGroup)
		template.Groups[channelconfig.ApplicationGroupKey].Values = nil
		template.Groups[channelconfig.ApplicationGroupKey].Policies = nil
	}

	updt, err := update.Compute(&cb.Config{ChannelGroup: template}, &cb.Config{ChannelGroup: newChannelGroup})
	if err != nil {
		err = errors.Wrapf(err, "%v could not compute update", logging.FuncInfo())
		return nil, err
	}

	// Add the consortium name to create the channel for into the write set as required.
	updt.ChannelId = channelID
	updt.ReadSet.Values[channelconfig.ConsortiumKey] = &cb.ConfigValue{Version: 0}
	updt.WriteSet.Values[channelconfig.ConsortiumKey] = &cb.ConfigValue{
		Version: 0,
		Value: utils.MarshalOrPanic(&cb.Consortium{
			Name: profile.Consortium,
		}),
	}

	// TODO: change when multiple orgs are in ordsyschannel
	for mspid, endpoints := range ordererEndpoints {
		endpointsValue := channelconfig.EndpointsValue(endpoints)
		endpointsValueBytes, _ := proto.Marshal(endpointsValue.Value())
		value := &cb.ConfigValue{Version: 0, Value: endpointsValueBytes, ModPolicy: "Admins"}
		updt.ReadSet.Groups[channelconfig.OrdererGroupKey] = &cb.ConfigGroup{
			ModPolicy: "Admins",
			Version:   0,
			Groups:    map[string]*cb.ConfigGroup{mspid: ag.Groups[mspid]},
		}
		updt.WriteSet.Groups[channelconfig.OrdererGroupKey] = proto.Clone(updt.ReadSet.Groups[channelconfig.OrdererGroupKey]).(*cb.ConfigGroup)
		updt.WriteSet.Groups[channelconfig.OrdererGroupKey].Groups[mspid].Version = 1
		updt.WriteSet.Groups[channelconfig.OrdererGroupKey].Groups[mspid].Values[channelconfig.EndpointsKey] = value
	}

	return updt, nil
}

// MakeChannelCreationTransaction is a handy utility function for creating transactions for channel creation
func MakeChannelCreationTransaction(channelID string, signer crypto.LocalSigner, orderingSystemChannelConfigGroup *cb.ConfigGroup, profile *genesisconfig.Profile, certs *fabric.Certs, ordererEndpoints map[string][]string, policy *ppb.FabricPolicy) (*cb.Envelope, error) {
	newChannelConfigUpdate, err := NewChannelCreateConfigUpdate(channelID, orderingSystemChannelConfigGroup, profile, certs, ordererEndpoints, policy)
	if err != nil {
		err = errors.Wrapf(err, "%v config update generation failed", logging.FuncInfo())
		return nil, err
	}

	newConfigUpdateEnv := &cb.ConfigUpdateEnvelope{
		ConfigUpdate: utils.MarshalOrPanic(newChannelConfigUpdate),
	}

	if signer != nil {
		sigHeader, err := signer.NewSignatureHeader()
		if err != nil {
			err = errors.Wrapf(err, "%v creating signature header failed", logging.FuncInfo())
			return nil, err
		}

		newConfigUpdateEnv.Signatures = []*cb.ConfigSignature{{
			SignatureHeader: utils.MarshalOrPanic(sigHeader),
		}}

		newConfigUpdateEnv.Signatures[0].Signature, err = signer.Sign(util.ConcatenateBytes(newConfigUpdateEnv.Signatures[0].SignatureHeader, newConfigUpdateEnv.ConfigUpdate))
		if err != nil {
			err = errors.Wrapf(err, "%v signature failure over config update", logging.FuncInfo())
			return nil, err
		}
	}

	return utils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelID, signer, newConfigUpdateEnv, msgVersion, epoch)
}

// Bootstrapper is a wrapper around NewChannelConfigGroup which can produce genesis blocks
type Bootstrapper struct {
	channelGroup *cb.ConfigGroup
}

// New creates a new Bootstrapper for generating genesis blocks
func New(config *genesisconfig.Profile, certs *fabric.Certs, policy *ppb.FabricPolicy) *Bootstrapper {
	logger := logging.GetLogger()
	channelGroup, err := NewChannelGroup(config, certs, policy)
	if err != nil {
		logger.Panic(fmt.Sprintf("Error creating channel group: %s", err))
	}
	return &Bootstrapper{
		channelGroup: channelGroup,
	}
}

// GenesisBlock produces a genesis block for the default test chain id
func (bs *Bootstrapper) GenesisBlock() *cb.Block {
	return genesis.NewFactoryImpl(bs.channelGroup).Block(genesisconfig.TestChainID)
}

// GenesisBlockForChannel produces a genesis block for a given channel ID
func (bs *Bootstrapper) GenesisBlockForChannel(channelID string) *cb.Block {
	return genesis.NewFactoryImpl(bs.channelGroup).Block(channelID)
}
