// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.21.7
// source: datadog/api/v1/api.proto

package pbgo

import (
	context "context"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_datadog_api_v1_api_proto protoreflect.FileDescriptor

var file_datadog_api_v1_api_proto_rawDesc = []byte{
	0x0a, 0x18, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31,
	0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2f, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x6f, 0x64,
	0x65, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x72,
	0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x71, 0x0a, 0x05,
	0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x68, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x21, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d,
	0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x6e,
	0x61, 0x6d, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x15, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0f,
	0x12, 0x0d, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x32,
	0xe4, 0x06, 0x0a, 0x0b, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x12,
	0x8f, 0x01, 0x0a, 0x14, 0x54, 0x61, 0x67, 0x67, 0x65, 0x72, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x12, 0x23, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64,
	0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x54, 0x61, 0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e,
	0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x54, 0x61, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x2a, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x24, 0x22, 0x1f, 0x2f, 0x76, 0x31,
	0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x3a, 0x01, 0x2a, 0x30,
	0x01, 0x12, 0x89, 0x01, 0x0a, 0x11, 0x54, 0x61, 0x67, 0x67, 0x65, 0x72, 0x46, 0x65, 0x74, 0x63,
	0x68, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x24, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x65, 0x74, 0x63, 0x68,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e,
	0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31,
	0x2e, 0x46, 0x65, 0x74, 0x63, 0x68, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x27, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x21, 0x22, 0x1c, 0x2f, 0x76,
	0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f, 0x66, 0x65,
	0x74, 0x63, 0x68, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x3a, 0x01, 0x2a, 0x12, 0x9b, 0x01,
	0x0a, 0x17, 0x44, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x43, 0x61, 0x70, 0x74, 0x75,
	0x72, 0x65, 0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x12, 0x27, 0x2e, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x61, 0x70,
	0x74, 0x75, 0x72, 0x65, 0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x28, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64,
	0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x54, 0x72, 0x69,
	0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2d, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x27, 0x22, 0x22, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x64,
	0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x2f, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65,
	0x2f, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x8c, 0x01, 0x0a, 0x17,
	0x44, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x53, 0x65, 0x74, 0x54, 0x61, 0x67, 0x67,
	0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1d, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x61, 0x67, 0x67, 0x65,
	0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x1a, 0x25, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67,
	0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x61, 0x67, 0x67, 0x65, 0x72,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2b, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x25, 0x22, 0x20, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f,
	0x64, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x2f, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72,
	0x65, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x01, 0x2a, 0x12, 0x8f, 0x01, 0x0a, 0x10, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x12,
	0x27, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x28, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64,
	0x6f, 0x67, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x28, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x22, 0x22, 0x1d, 0x2f, 0x76, 0x31, 0x2f,
	0x67, 0x72, 0x70, 0x63, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x3a, 0x01, 0x2a, 0x12, 0x78, 0x0a, 0x0e,
	0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x26, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x26,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x20, 0x22, 0x1b, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x3a, 0x01, 0x2a, 0x42, 0x10, 0x5a, 0x0e, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x62, 0x67, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_datadog_api_v1_api_proto_goTypes = []interface{}{
	(*HostnameRequest)(nil),          // 0: datadog.model.v1.HostnameRequest
	(*StreamTagsRequest)(nil),        // 1: datadog.model.v1.StreamTagsRequest
	(*FetchEntityRequest)(nil),       // 2: datadog.model.v1.FetchEntityRequest
	(*CaptureTriggerRequest)(nil),    // 3: datadog.model.v1.CaptureTriggerRequest
	(*TaggerState)(nil),              // 4: datadog.model.v1.TaggerState
	(*ClientGetConfigsRequest)(nil),  // 5: datadog.config.ClientGetConfigsRequest
	(*emptypb.Empty)(nil),            // 6: google.protobuf.Empty
	(*HostnameReply)(nil),            // 7: datadog.model.v1.HostnameReply
	(*StreamTagsResponse)(nil),       // 8: datadog.model.v1.StreamTagsResponse
	(*FetchEntityResponse)(nil),      // 9: datadog.model.v1.FetchEntityResponse
	(*CaptureTriggerResponse)(nil),   // 10: datadog.model.v1.CaptureTriggerResponse
	(*TaggerStateResponse)(nil),      // 11: datadog.model.v1.TaggerStateResponse
	(*ClientGetConfigsResponse)(nil), // 12: datadog.config.ClientGetConfigsResponse
	(*GetStateConfigResponse)(nil),   // 13: datadog.config.GetStateConfigResponse
}
var file_datadog_api_v1_api_proto_depIdxs = []int32{
	0,  // 0: datadog.api.v1.Agent.GetHostname:input_type -> datadog.model.v1.HostnameRequest
	1,  // 1: datadog.api.v1.AgentSecure.TaggerStreamEntities:input_type -> datadog.model.v1.StreamTagsRequest
	2,  // 2: datadog.api.v1.AgentSecure.TaggerFetchEntity:input_type -> datadog.model.v1.FetchEntityRequest
	3,  // 3: datadog.api.v1.AgentSecure.DogstatsdCaptureTrigger:input_type -> datadog.model.v1.CaptureTriggerRequest
	4,  // 4: datadog.api.v1.AgentSecure.DogstatsdSetTaggerState:input_type -> datadog.model.v1.TaggerState
	5,  // 5: datadog.api.v1.AgentSecure.ClientGetConfigs:input_type -> datadog.config.ClientGetConfigsRequest
	6,  // 6: datadog.api.v1.AgentSecure.GetConfigState:input_type -> google.protobuf.Empty
	7,  // 7: datadog.api.v1.Agent.GetHostname:output_type -> datadog.model.v1.HostnameReply
	8,  // 8: datadog.api.v1.AgentSecure.TaggerStreamEntities:output_type -> datadog.model.v1.StreamTagsResponse
	9,  // 9: datadog.api.v1.AgentSecure.TaggerFetchEntity:output_type -> datadog.model.v1.FetchEntityResponse
	10, // 10: datadog.api.v1.AgentSecure.DogstatsdCaptureTrigger:output_type -> datadog.model.v1.CaptureTriggerResponse
	11, // 11: datadog.api.v1.AgentSecure.DogstatsdSetTaggerState:output_type -> datadog.model.v1.TaggerStateResponse
	12, // 12: datadog.api.v1.AgentSecure.ClientGetConfigs:output_type -> datadog.config.ClientGetConfigsResponse
	13, // 13: datadog.api.v1.AgentSecure.GetConfigState:output_type -> datadog.config.GetStateConfigResponse
	7,  // [7:14] is the sub-list for method output_type
	0,  // [0:7] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_datadog_api_v1_api_proto_init() }
func file_datadog_api_v1_api_proto_init() {
	if File_datadog_api_v1_api_proto != nil {
		return
	}
	file_datadog_model_v1_model_proto_init()
	file_datadog_remoteconfig_remoteconfig_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_datadog_api_v1_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_datadog_api_v1_api_proto_goTypes,
		DependencyIndexes: file_datadog_api_v1_api_proto_depIdxs,
	}.Build()
	File_datadog_api_v1_api_proto = out.File
	file_datadog_api_v1_api_proto_rawDesc = nil
	file_datadog_api_v1_api_proto_goTypes = nil
	file_datadog_api_v1_api_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// AgentClient is the client API for Agent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AgentClient interface {
	// get the hostname
	GetHostname(ctx context.Context, in *HostnameRequest, opts ...grpc.CallOption) (*HostnameReply, error)
}

type agentClient struct {
	cc grpc.ClientConnInterface
}

func NewAgentClient(cc grpc.ClientConnInterface) AgentClient {
	return &agentClient{cc}
}

func (c *agentClient) GetHostname(ctx context.Context, in *HostnameRequest, opts ...grpc.CallOption) (*HostnameReply, error) {
	out := new(HostnameReply)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.Agent/GetHostname", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AgentServer is the server API for Agent service.
type AgentServer interface {
	// get the hostname
	GetHostname(context.Context, *HostnameRequest) (*HostnameReply, error)
}

// UnimplementedAgentServer can be embedded to have forward compatible implementations.
type UnimplementedAgentServer struct {
}

func (*UnimplementedAgentServer) GetHostname(context.Context, *HostnameRequest) (*HostnameReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHostname not implemented")
}

func RegisterAgentServer(s *grpc.Server, srv AgentServer) {
	s.RegisterService(&_Agent_serviceDesc, srv)
}

func _Agent_GetHostname_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HostnameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServer).GetHostname(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.Agent/GetHostname",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentServer).GetHostname(ctx, req.(*HostnameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Agent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "datadog.api.v1.Agent",
	HandlerType: (*AgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetHostname",
			Handler:    _Agent_GetHostname_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "datadog/api/v1/api.proto",
}

// AgentSecureClient is the client API for AgentSecure service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AgentSecureClient interface {
	// subscribes to added, removed, or changed entities in the Tagger
	// and streams them to clients as events.
	// can be called through the HTTP gateway, and events will be streamed as JSON:
	//
	//	  $  curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//	     -XPOST -k https://localhost:5001/v1/grpc/tagger/stream_entities
	//	  {
	//	   "result": {
	//	       "entity": {
	//	           "id": {
	//	               "prefix": "kubernetes_pod_uid",
	//	               "uid": "4025461f832caf3fceb7fc2a32f879c6"
	//	           },
	//	           "hash": "cad4fc8fc409fcc1",
	//	           "lowCardinalityTags": [
	//	               "kube_namespace:kube-system",
	//	               "pod_phase:running"
	//	           ]
	//	       }
	//	   }
	//	}
	TaggerStreamEntities(ctx context.Context, in *StreamTagsRequest, opts ...grpc.CallOption) (AgentSecure_TaggerStreamEntitiesClient, error)
	// fetches an entity from the Tagger with the desired cardinality tags.
	// can be called through the HTTP gateway, and entity will be returned as JSON:
	//
	//	  $ curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//	     -XPOST -k -H "Content-Type: application/json" \
	//	     --data '{"id":{"prefix":"kubernetes_pod_uid","uid":"d575fb58-82dc-418e-bfb1-aececc9bc507"}}' \
	//	     https://localhost:5001/v1/grpc/tagger/fetch_entity
	//	  {
	//	   "id": {
	//	       "prefix": "kubernetes_pod_uid",
	//	       "uid": "d575fb58-82dc-418e-bfb1-aececc9bc507"
	//	   },
	//	   "tags": [
	//	       "kube_namespace:kube-system",
	//	       "pod_phase:running",
	//	       "kube_deployment:coredns",
	//	       "kube_service:kube-dns"
	//	   ]
	//	}
	TaggerFetchEntity(ctx context.Context, in *FetchEntityRequest, opts ...grpc.CallOption) (*FetchEntityResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//
	//	TODO: add the curl code here
	DogstatsdCaptureTrigger(ctx context.Context, in *CaptureTriggerRequest, opts ...grpc.CallOption) (*CaptureTriggerResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//
	//	TODO: add the curl code here
	DogstatsdSetTaggerState(ctx context.Context, in *TaggerState, opts ...grpc.CallOption) (*TaggerStateResponse, error)
	ClientGetConfigs(ctx context.Context, in *ClientGetConfigsRequest, opts ...grpc.CallOption) (*ClientGetConfigsResponse, error)
	GetConfigState(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*GetStateConfigResponse, error)
}

type agentSecureClient struct {
	cc grpc.ClientConnInterface
}

func NewAgentSecureClient(cc grpc.ClientConnInterface) AgentSecureClient {
	return &agentSecureClient{cc}
}

func (c *agentSecureClient) TaggerStreamEntities(ctx context.Context, in *StreamTagsRequest, opts ...grpc.CallOption) (AgentSecure_TaggerStreamEntitiesClient, error) {
	stream, err := c.cc.NewStream(ctx, &_AgentSecure_serviceDesc.Streams[0], "/datadog.api.v1.AgentSecure/TaggerStreamEntities", opts...)
	if err != nil {
		return nil, err
	}
	x := &agentSecureTaggerStreamEntitiesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type AgentSecure_TaggerStreamEntitiesClient interface {
	Recv() (*StreamTagsResponse, error)
	grpc.ClientStream
}

type agentSecureTaggerStreamEntitiesClient struct {
	grpc.ClientStream
}

func (x *agentSecureTaggerStreamEntitiesClient) Recv() (*StreamTagsResponse, error) {
	m := new(StreamTagsResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentSecureClient) TaggerFetchEntity(ctx context.Context, in *FetchEntityRequest, opts ...grpc.CallOption) (*FetchEntityResponse, error) {
	out := new(FetchEntityResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/TaggerFetchEntity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) DogstatsdCaptureTrigger(ctx context.Context, in *CaptureTriggerRequest, opts ...grpc.CallOption) (*CaptureTriggerResponse, error) {
	out := new(CaptureTriggerResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/DogstatsdCaptureTrigger", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) DogstatsdSetTaggerState(ctx context.Context, in *TaggerState, opts ...grpc.CallOption) (*TaggerStateResponse, error) {
	out := new(TaggerStateResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/DogstatsdSetTaggerState", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) ClientGetConfigs(ctx context.Context, in *ClientGetConfigsRequest, opts ...grpc.CallOption) (*ClientGetConfigsResponse, error) {
	out := new(ClientGetConfigsResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/ClientGetConfigs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) GetConfigState(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*GetStateConfigResponse, error) {
	out := new(GetStateConfigResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/GetConfigState", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AgentSecureServer is the server API for AgentSecure service.
type AgentSecureServer interface {
	// subscribes to added, removed, or changed entities in the Tagger
	// and streams them to clients as events.
	// can be called through the HTTP gateway, and events will be streamed as JSON:
	//
	//	  $  curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//	     -XPOST -k https://localhost:5001/v1/grpc/tagger/stream_entities
	//	  {
	//	   "result": {
	//	       "entity": {
	//	           "id": {
	//	               "prefix": "kubernetes_pod_uid",
	//	               "uid": "4025461f832caf3fceb7fc2a32f879c6"
	//	           },
	//	           "hash": "cad4fc8fc409fcc1",
	//	           "lowCardinalityTags": [
	//	               "kube_namespace:kube-system",
	//	               "pod_phase:running"
	//	           ]
	//	       }
	//	   }
	//	}
	TaggerStreamEntities(*StreamTagsRequest, AgentSecure_TaggerStreamEntitiesServer) error
	// fetches an entity from the Tagger with the desired cardinality tags.
	// can be called through the HTTP gateway, and entity will be returned as JSON:
	//
	//	  $ curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//	     -XPOST -k -H "Content-Type: application/json" \
	//	     --data '{"id":{"prefix":"kubernetes_pod_uid","uid":"d575fb58-82dc-418e-bfb1-aececc9bc507"}}' \
	//	     https://localhost:5001/v1/grpc/tagger/fetch_entity
	//	  {
	//	   "id": {
	//	       "prefix": "kubernetes_pod_uid",
	//	       "uid": "d575fb58-82dc-418e-bfb1-aececc9bc507"
	//	   },
	//	   "tags": [
	//	       "kube_namespace:kube-system",
	//	       "pod_phase:running",
	//	       "kube_deployment:coredns",
	//	       "kube_service:kube-dns"
	//	   ]
	//	}
	TaggerFetchEntity(context.Context, *FetchEntityRequest) (*FetchEntityResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//
	//	TODO: add the curl code here
	DogstatsdCaptureTrigger(context.Context, *CaptureTriggerRequest) (*CaptureTriggerResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//
	//	TODO: add the curl code here
	DogstatsdSetTaggerState(context.Context, *TaggerState) (*TaggerStateResponse, error)
	ClientGetConfigs(context.Context, *ClientGetConfigsRequest) (*ClientGetConfigsResponse, error)
	GetConfigState(context.Context, *emptypb.Empty) (*GetStateConfigResponse, error)
}

// UnimplementedAgentSecureServer can be embedded to have forward compatible implementations.
type UnimplementedAgentSecureServer struct {
}

func (*UnimplementedAgentSecureServer) TaggerStreamEntities(*StreamTagsRequest, AgentSecure_TaggerStreamEntitiesServer) error {
	return status.Errorf(codes.Unimplemented, "method TaggerStreamEntities not implemented")
}
func (*UnimplementedAgentSecureServer) TaggerFetchEntity(context.Context, *FetchEntityRequest) (*FetchEntityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TaggerFetchEntity not implemented")
}
func (*UnimplementedAgentSecureServer) DogstatsdCaptureTrigger(context.Context, *CaptureTriggerRequest) (*CaptureTriggerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DogstatsdCaptureTrigger not implemented")
}
func (*UnimplementedAgentSecureServer) DogstatsdSetTaggerState(context.Context, *TaggerState) (*TaggerStateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DogstatsdSetTaggerState not implemented")
}
func (*UnimplementedAgentSecureServer) ClientGetConfigs(context.Context, *ClientGetConfigsRequest) (*ClientGetConfigsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ClientGetConfigs not implemented")
}
func (*UnimplementedAgentSecureServer) GetConfigState(context.Context, *emptypb.Empty) (*GetStateConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfigState not implemented")
}

func RegisterAgentSecureServer(s *grpc.Server, srv AgentSecureServer) {
	s.RegisterService(&_AgentSecure_serviceDesc, srv)
}

func _AgentSecure_TaggerStreamEntities_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(StreamTagsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(AgentSecureServer).TaggerStreamEntities(m, &agentSecureTaggerStreamEntitiesServer{stream})
}

type AgentSecure_TaggerStreamEntitiesServer interface {
	Send(*StreamTagsResponse) error
	grpc.ServerStream
}

type agentSecureTaggerStreamEntitiesServer struct {
	grpc.ServerStream
}

func (x *agentSecureTaggerStreamEntitiesServer) Send(m *StreamTagsResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _AgentSecure_TaggerFetchEntity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchEntityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).TaggerFetchEntity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/TaggerFetchEntity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).TaggerFetchEntity(ctx, req.(*FetchEntityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_DogstatsdCaptureTrigger_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CaptureTriggerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).DogstatsdCaptureTrigger(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/DogstatsdCaptureTrigger",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).DogstatsdCaptureTrigger(ctx, req.(*CaptureTriggerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_DogstatsdSetTaggerState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TaggerState)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).DogstatsdSetTaggerState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/DogstatsdSetTaggerState",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).DogstatsdSetTaggerState(ctx, req.(*TaggerState))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_ClientGetConfigs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClientGetConfigsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).ClientGetConfigs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/ClientGetConfigs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).ClientGetConfigs(ctx, req.(*ClientGetConfigsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_GetConfigState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).GetConfigState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/GetConfigState",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).GetConfigState(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _AgentSecure_serviceDesc = grpc.ServiceDesc{
	ServiceName: "datadog.api.v1.AgentSecure",
	HandlerType: (*AgentSecureServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TaggerFetchEntity",
			Handler:    _AgentSecure_TaggerFetchEntity_Handler,
		},
		{
			MethodName: "DogstatsdCaptureTrigger",
			Handler:    _AgentSecure_DogstatsdCaptureTrigger_Handler,
		},
		{
			MethodName: "DogstatsdSetTaggerState",
			Handler:    _AgentSecure_DogstatsdSetTaggerState_Handler,
		},
		{
			MethodName: "ClientGetConfigs",
			Handler:    _AgentSecure_ClientGetConfigs_Handler,
		},
		{
			MethodName: "GetConfigState",
			Handler:    _AgentSecure_GetConfigState_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "TaggerStreamEntities",
			Handler:       _AgentSecure_TaggerStreamEntities_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "datadog/api/v1/api.proto",
}
