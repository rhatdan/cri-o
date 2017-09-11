package libkpod

import (
	"k8s.io/apimachinery/pkg/fields"
	pb "k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"

	"github.com/kubernetes-incubator/cri-o/oci"
	"github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ContainerData handles the data used when inspecting a container
type ContainerData struct {
	ID               string
	Name             string
	LogPath          string
	Labels           fields.Set
	Annotations      fields.Set
	State            *oci.ContainerState
	Metadata         *pb.ContainerMetadata
	BundlePath       string
	StopSignal       string
	FromImage        string `json:"Image,omitempty"`
	FromImageID      string `json:"ImageID"`
	MountPoint       string `json:"Mountpoint,omitempty"`
	MountLabel       string
	Mounts           []specs.Mount
	AppArmorProfile  string
	ImageAnnotations map[string]string `json:"Annotations,omitempty"`
	ImageCreatedBy   string            `json:"CreatedBy,omitempty"`
	Config           v1.ImageConfig    `json:"Config,omitempty"`
	SizeRw           uint              `json:"SizeRw,omitempty"`
	SizeRootFs       uint              `json:"SizeRootFs,omitempty"`
	Args             []string
	ResolvConfPath   string
	HostnamePath     string
	HostsPath        string
	GraphDriver      driverData
}

type driverData struct {
	Name string
	Data map[string]string
}

// Get an oci.Container and update its status
func (c *ContainerServer) inspectContainer(container string) (*oci.Container, error) {
	ociCtr, err := c.LookupContainer(container)
	if err != nil {
		return nil, err
	}
	// call runtime.UpdateStatus()
	err = c.Runtime().UpdateStatus(ociCtr)
	if err != nil {
		return nil, err
	}
	return ociCtr, nil
}

func getBlankSpec() specs.Spec {
	return specs.Spec{
		Process:     &specs.Process{},
		Root:        &specs.Root{},
		Mounts:      []specs.Mount{},
		Hooks:       &specs.Hooks{},
		Annotations: make(map[string]string),
		Linux:       &specs.Linux{},
		Solaris:     &specs.Solaris{},
		Windows:     &specs.Windows{},
	}
}
