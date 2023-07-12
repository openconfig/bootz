package client

import (
	"context"

	"github.com/openconfig/bootz/proto/bootz"
	"google.golang.org/grpc/grpc"
)

type Client struct {
	bootz.BootstrapClient
}

func (c *Client) GetBootstrapData(ctx context.Context, req *bootz.GetBootstrapDataRequest, opts ...grpc.CallOption) (*bootz.GetBootstrapDataResponse, error) {

}
func (c *Client) ReportStatus(ctx context.Context, req *bootz.ReportStatusRequest, opts ...grpc.CallOption) (*bootz.EmptyResponse, error) {

}
