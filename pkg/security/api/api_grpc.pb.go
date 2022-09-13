// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.12.4
// source: pkg/security/api/api.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SecurityModuleClient is the client API for SecurityModule service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SecurityModuleClient interface {
	GetEvents(ctx context.Context, in *GetEventParams, opts ...grpc.CallOption) (SecurityModule_GetEventsClient, error)
	GetProcessEvents(ctx context.Context, in *GetProcessEventParams, opts ...grpc.CallOption) (SecurityModule_GetProcessEventsClient, error)
	DumpProcessCache(ctx context.Context, in *DumpProcessCacheParams, opts ...grpc.CallOption) (*SecurityDumpProcessCacheMessage, error)
	GetConfig(ctx context.Context, in *GetConfigParams, opts ...grpc.CallOption) (*SecurityConfigMessage, error)
	GetStatus(ctx context.Context, in *GetStatusParams, opts ...grpc.CallOption) (*Status, error)
	RunSelfTest(ctx context.Context, in *RunSelfTestParams, opts ...grpc.CallOption) (*SecuritySelfTestResultMessage, error)
	ReloadPolicies(ctx context.Context, in *ReloadPoliciesParams, opts ...grpc.CallOption) (*ReloadPoliciesResultMessage, error)
	DumpNetworkNamespace(ctx context.Context, in *DumpNetworkNamespaceParams, opts ...grpc.CallOption) (*DumpNetworkNamespaceMessage, error)
	DumpDiscarders(ctx context.Context, in *DumpDiscardersParams, opts ...grpc.CallOption) (*DumpDiscardersMessage, error)
	// Activity dumps
	DumpActivity(ctx context.Context, in *ActivityDumpParams, opts ...grpc.CallOption) (*ActivityDumpMessage, error)
	ListActivityDumps(ctx context.Context, in *ActivityDumpListParams, opts ...grpc.CallOption) (*ActivityDumpListMessage, error)
	StopActivityDump(ctx context.Context, in *ActivityDumpStopParams, opts ...grpc.CallOption) (*ActivityDumpStopMessage, error)
	TranscodingRequest(ctx context.Context, in *TranscodingRequestParams, opts ...grpc.CallOption) (*TranscodingRequestMessage, error)
	GetActivityDumpStream(ctx context.Context, in *ActivityDumpStreamParams, opts ...grpc.CallOption) (SecurityModule_GetActivityDumpStreamClient, error)
}

type securityModuleClient struct {
	cc grpc.ClientConnInterface
}

func NewSecurityModuleClient(cc grpc.ClientConnInterface) SecurityModuleClient {
	return &securityModuleClient{cc}
}

func (c *securityModuleClient) GetEvents(ctx context.Context, in *GetEventParams, opts ...grpc.CallOption) (SecurityModule_GetEventsClient, error) {
	stream, err := c.cc.NewStream(ctx, &SecurityModule_ServiceDesc.Streams[0], "/api.SecurityModule/GetEvents", opts...)
	if err != nil {
		return nil, err
	}
	x := &securityModuleGetEventsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SecurityModule_GetEventsClient interface {
	Recv() (*SecurityEventMessage, error)
	grpc.ClientStream
}

type securityModuleGetEventsClient struct {
	grpc.ClientStream
}

func (x *securityModuleGetEventsClient) Recv() (*SecurityEventMessage, error) {
	m := new(SecurityEventMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *securityModuleClient) GetProcessEvents(ctx context.Context, in *GetProcessEventParams, opts ...grpc.CallOption) (SecurityModule_GetProcessEventsClient, error) {
	stream, err := c.cc.NewStream(ctx, &SecurityModule_ServiceDesc.Streams[1], "/api.SecurityModule/GetProcessEvents", opts...)
	if err != nil {
		return nil, err
	}
	x := &securityModuleGetProcessEventsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SecurityModule_GetProcessEventsClient interface {
	Recv() (*SecurityProcessEventMessage, error)
	grpc.ClientStream
}

type securityModuleGetProcessEventsClient struct {
	grpc.ClientStream
}

func (x *securityModuleGetProcessEventsClient) Recv() (*SecurityProcessEventMessage, error) {
	m := new(SecurityProcessEventMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *securityModuleClient) DumpProcessCache(ctx context.Context, in *DumpProcessCacheParams, opts ...grpc.CallOption) (*SecurityDumpProcessCacheMessage, error) {
	out := new(SecurityDumpProcessCacheMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/DumpProcessCache", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) GetConfig(ctx context.Context, in *GetConfigParams, opts ...grpc.CallOption) (*SecurityConfigMessage, error) {
	out := new(SecurityConfigMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/GetConfig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) GetStatus(ctx context.Context, in *GetStatusParams, opts ...grpc.CallOption) (*Status, error) {
	out := new(Status)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/GetStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) RunSelfTest(ctx context.Context, in *RunSelfTestParams, opts ...grpc.CallOption) (*SecuritySelfTestResultMessage, error) {
	out := new(SecuritySelfTestResultMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/RunSelfTest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) ReloadPolicies(ctx context.Context, in *ReloadPoliciesParams, opts ...grpc.CallOption) (*ReloadPoliciesResultMessage, error) {
	out := new(ReloadPoliciesResultMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/ReloadPolicies", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) DumpNetworkNamespace(ctx context.Context, in *DumpNetworkNamespaceParams, opts ...grpc.CallOption) (*DumpNetworkNamespaceMessage, error) {
	out := new(DumpNetworkNamespaceMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/DumpNetworkNamespace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) DumpDiscarders(ctx context.Context, in *DumpDiscardersParams, opts ...grpc.CallOption) (*DumpDiscardersMessage, error) {
	out := new(DumpDiscardersMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/DumpDiscarders", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) DumpActivity(ctx context.Context, in *ActivityDumpParams, opts ...grpc.CallOption) (*ActivityDumpMessage, error) {
	out := new(ActivityDumpMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/DumpActivity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) ListActivityDumps(ctx context.Context, in *ActivityDumpListParams, opts ...grpc.CallOption) (*ActivityDumpListMessage, error) {
	out := new(ActivityDumpListMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/ListActivityDumps", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) StopActivityDump(ctx context.Context, in *ActivityDumpStopParams, opts ...grpc.CallOption) (*ActivityDumpStopMessage, error) {
	out := new(ActivityDumpStopMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/StopActivityDump", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) TranscodingRequest(ctx context.Context, in *TranscodingRequestParams, opts ...grpc.CallOption) (*TranscodingRequestMessage, error) {
	out := new(TranscodingRequestMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/TranscodingRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) GetActivityDumpStream(ctx context.Context, in *ActivityDumpStreamParams, opts ...grpc.CallOption) (SecurityModule_GetActivityDumpStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &SecurityModule_ServiceDesc.Streams[2], "/api.SecurityModule/GetActivityDumpStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &securityModuleGetActivityDumpStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SecurityModule_GetActivityDumpStreamClient interface {
	Recv() (*ActivityDumpStreamMessage, error)
	grpc.ClientStream
}

type securityModuleGetActivityDumpStreamClient struct {
	grpc.ClientStream
}

func (x *securityModuleGetActivityDumpStreamClient) Recv() (*ActivityDumpStreamMessage, error) {
	m := new(ActivityDumpStreamMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SecurityModuleServer is the server API for SecurityModule service.
// All implementations must embed UnimplementedSecurityModuleServer
// for forward compatibility
type SecurityModuleServer interface {
	GetEvents(*GetEventParams, SecurityModule_GetEventsServer) error
	GetProcessEvents(*GetProcessEventParams, SecurityModule_GetProcessEventsServer) error
	DumpProcessCache(context.Context, *DumpProcessCacheParams) (*SecurityDumpProcessCacheMessage, error)
	GetConfig(context.Context, *GetConfigParams) (*SecurityConfigMessage, error)
	GetStatus(context.Context, *GetStatusParams) (*Status, error)
	RunSelfTest(context.Context, *RunSelfTestParams) (*SecuritySelfTestResultMessage, error)
	ReloadPolicies(context.Context, *ReloadPoliciesParams) (*ReloadPoliciesResultMessage, error)
	DumpNetworkNamespace(context.Context, *DumpNetworkNamespaceParams) (*DumpNetworkNamespaceMessage, error)
	DumpDiscarders(context.Context, *DumpDiscardersParams) (*DumpDiscardersMessage, error)
	// Activity dumps
	DumpActivity(context.Context, *ActivityDumpParams) (*ActivityDumpMessage, error)
	ListActivityDumps(context.Context, *ActivityDumpListParams) (*ActivityDumpListMessage, error)
	StopActivityDump(context.Context, *ActivityDumpStopParams) (*ActivityDumpStopMessage, error)
	TranscodingRequest(context.Context, *TranscodingRequestParams) (*TranscodingRequestMessage, error)
	GetActivityDumpStream(*ActivityDumpStreamParams, SecurityModule_GetActivityDumpStreamServer) error
	mustEmbedUnimplementedSecurityModuleServer()
}

// UnimplementedSecurityModuleServer must be embedded to have forward compatible implementations.
type UnimplementedSecurityModuleServer struct {
}

func (UnimplementedSecurityModuleServer) GetEvents(*GetEventParams, SecurityModule_GetEventsServer) error {
	return status.Errorf(codes.Unimplemented, "method GetEvents not implemented")
}
func (UnimplementedSecurityModuleServer) GetProcessEvents(*GetProcessEventParams, SecurityModule_GetProcessEventsServer) error {
	return status.Errorf(codes.Unimplemented, "method GetProcessEvents not implemented")
}
func (UnimplementedSecurityModuleServer) DumpProcessCache(context.Context, *DumpProcessCacheParams) (*SecurityDumpProcessCacheMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DumpProcessCache not implemented")
}
func (UnimplementedSecurityModuleServer) GetConfig(context.Context, *GetConfigParams) (*SecurityConfigMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfig not implemented")
}
func (UnimplementedSecurityModuleServer) GetStatus(context.Context, *GetStatusParams) (*Status, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStatus not implemented")
}
func (UnimplementedSecurityModuleServer) RunSelfTest(context.Context, *RunSelfTestParams) (*SecuritySelfTestResultMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RunSelfTest not implemented")
}
func (UnimplementedSecurityModuleServer) ReloadPolicies(context.Context, *ReloadPoliciesParams) (*ReloadPoliciesResultMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReloadPolicies not implemented")
}
func (UnimplementedSecurityModuleServer) DumpNetworkNamespace(context.Context, *DumpNetworkNamespaceParams) (*DumpNetworkNamespaceMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DumpNetworkNamespace not implemented")
}
func (UnimplementedSecurityModuleServer) DumpDiscarders(context.Context, *DumpDiscardersParams) (*DumpDiscardersMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DumpDiscarders not implemented")
}
func (UnimplementedSecurityModuleServer) DumpActivity(context.Context, *ActivityDumpParams) (*ActivityDumpMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DumpActivity not implemented")
}
func (UnimplementedSecurityModuleServer) ListActivityDumps(context.Context, *ActivityDumpListParams) (*ActivityDumpListMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListActivityDumps not implemented")
}
func (UnimplementedSecurityModuleServer) StopActivityDump(context.Context, *ActivityDumpStopParams) (*ActivityDumpStopMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopActivityDump not implemented")
}
func (UnimplementedSecurityModuleServer) TranscodingRequest(context.Context, *TranscodingRequestParams) (*TranscodingRequestMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TranscodingRequest not implemented")
}
func (UnimplementedSecurityModuleServer) GetActivityDumpStream(*ActivityDumpStreamParams, SecurityModule_GetActivityDumpStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GetActivityDumpStream not implemented")
}
func (UnimplementedSecurityModuleServer) mustEmbedUnimplementedSecurityModuleServer() {}

// UnsafeSecurityModuleServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SecurityModuleServer will
// result in compilation errors.
type UnsafeSecurityModuleServer interface {
	mustEmbedUnimplementedSecurityModuleServer()
}

func RegisterSecurityModuleServer(s grpc.ServiceRegistrar, srv SecurityModuleServer) {
	s.RegisterService(&SecurityModule_ServiceDesc, srv)
}

func _SecurityModule_GetEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetEventParams)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SecurityModuleServer).GetEvents(m, &securityModuleGetEventsServer{stream})
}

type SecurityModule_GetEventsServer interface {
	Send(*SecurityEventMessage) error
	grpc.ServerStream
}

type securityModuleGetEventsServer struct {
	grpc.ServerStream
}

func (x *securityModuleGetEventsServer) Send(m *SecurityEventMessage) error {
	return x.ServerStream.SendMsg(m)
}

func _SecurityModule_GetProcessEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetProcessEventParams)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SecurityModuleServer).GetProcessEvents(m, &securityModuleGetProcessEventsServer{stream})
}

type SecurityModule_GetProcessEventsServer interface {
	Send(*SecurityProcessEventMessage) error
	grpc.ServerStream
}

type securityModuleGetProcessEventsServer struct {
	grpc.ServerStream
}

func (x *securityModuleGetProcessEventsServer) Send(m *SecurityProcessEventMessage) error {
	return x.ServerStream.SendMsg(m)
}

func _SecurityModule_DumpProcessCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DumpProcessCacheParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).DumpProcessCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/DumpProcessCache",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).DumpProcessCache(ctx, req.(*DumpProcessCacheParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_GetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetConfigParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).GetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/GetConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).GetConfig(ctx, req.(*GetConfigParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_GetStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetStatusParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).GetStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/GetStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).GetStatus(ctx, req.(*GetStatusParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_RunSelfTest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RunSelfTestParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).RunSelfTest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/RunSelfTest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).RunSelfTest(ctx, req.(*RunSelfTestParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_ReloadPolicies_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReloadPoliciesParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).ReloadPolicies(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/ReloadPolicies",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).ReloadPolicies(ctx, req.(*ReloadPoliciesParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_DumpNetworkNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DumpNetworkNamespaceParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).DumpNetworkNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/DumpNetworkNamespace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).DumpNetworkNamespace(ctx, req.(*DumpNetworkNamespaceParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_DumpDiscarders_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DumpDiscardersParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).DumpDiscarders(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/DumpDiscarders",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).DumpDiscarders(ctx, req.(*DumpDiscardersParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_DumpActivity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivityDumpParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).DumpActivity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/DumpActivity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).DumpActivity(ctx, req.(*ActivityDumpParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_ListActivityDumps_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivityDumpListParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).ListActivityDumps(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/ListActivityDumps",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).ListActivityDumps(ctx, req.(*ActivityDumpListParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_StopActivityDump_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivityDumpStopParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).StopActivityDump(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/StopActivityDump",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).StopActivityDump(ctx, req.(*ActivityDumpStopParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_TranscodingRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TranscodingRequestParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).TranscodingRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/TranscodingRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).TranscodingRequest(ctx, req.(*TranscodingRequestParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_GetActivityDumpStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ActivityDumpStreamParams)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SecurityModuleServer).GetActivityDumpStream(m, &securityModuleGetActivityDumpStreamServer{stream})
}

type SecurityModule_GetActivityDumpStreamServer interface {
	Send(*ActivityDumpStreamMessage) error
	grpc.ServerStream
}

type securityModuleGetActivityDumpStreamServer struct {
	grpc.ServerStream
}

func (x *securityModuleGetActivityDumpStreamServer) Send(m *ActivityDumpStreamMessage) error {
	return x.ServerStream.SendMsg(m)
}

// SecurityModule_ServiceDesc is the grpc.ServiceDesc for SecurityModule service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SecurityModule_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.SecurityModule",
	HandlerType: (*SecurityModuleServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DumpProcessCache",
			Handler:    _SecurityModule_DumpProcessCache_Handler,
		},
		{
			MethodName: "GetConfig",
			Handler:    _SecurityModule_GetConfig_Handler,
		},
		{
			MethodName: "GetStatus",
			Handler:    _SecurityModule_GetStatus_Handler,
		},
		{
			MethodName: "RunSelfTest",
			Handler:    _SecurityModule_RunSelfTest_Handler,
		},
		{
			MethodName: "ReloadPolicies",
			Handler:    _SecurityModule_ReloadPolicies_Handler,
		},
		{
			MethodName: "DumpNetworkNamespace",
			Handler:    _SecurityModule_DumpNetworkNamespace_Handler,
		},
		{
			MethodName: "DumpDiscarders",
			Handler:    _SecurityModule_DumpDiscarders_Handler,
		},
		{
			MethodName: "DumpActivity",
			Handler:    _SecurityModule_DumpActivity_Handler,
		},
		{
			MethodName: "ListActivityDumps",
			Handler:    _SecurityModule_ListActivityDumps_Handler,
		},
		{
			MethodName: "StopActivityDump",
			Handler:    _SecurityModule_StopActivityDump_Handler,
		},
		{
			MethodName: "TranscodingRequest",
			Handler:    _SecurityModule_TranscodingRequest_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetEvents",
			Handler:       _SecurityModule_GetEvents_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetProcessEvents",
			Handler:       _SecurityModule_GetProcessEvents_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetActivityDumpStream",
			Handler:       _SecurityModule_GetActivityDumpStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "pkg/security/api/api.proto",
}
