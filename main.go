package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Ec2Instance struct {
	ID             string
	Name           string
	PublicIP       string
	SecurityGroups []SecurityGroups
}

type SecurityGroups struct {
	ID              string
	Name            string
	PortsAccessible []PortAccessible
}

type PortAccessible struct {
	Port         int32
	Protocol     string
	SourceRanges []string
}

func main() {
	//This is my setup monologue. This app is a film. It's a production.
	fmt.Println("Hello! This is the Automatic APT™.")
	fmt.Println("You are running me in order to hack your own services.")
	fmt.Println("I will let you know what's vulnerable. Stand by.")
	fmt.Println("------------------")

	// Get STS client
	ctx := context.TODO()
	stsClient := newSTSClient(ctx)

	// Call GetCallerIdentity to get account information
	result, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("AWS Account ID: %s\n", *result.Account)

	// Analyze EC2 instances
	fmt.Printf("Analyzing EC2 instances for AWS Account: %s\n\n", *result.Account)
	ec2Client := newEC2Client(ctx)
	instances, err := analyzeEc2Instances(ctx, ec2Client)
	if err != nil {
		log.Fatal(err)
	}

	// Print results
	for _, instance := range instances {
		fmt.Printf("Instance ID: %s\n", instance.ID)
		if instance.Name != "" {
			fmt.Printf("Name: %s\n", instance.Name)
		}
		if instance.PublicIP != "" {
			fmt.Printf("Public IP: %s\n", instance.PublicIP)
		}

		fmt.Println("Security Groups:")
		for _, sg := range instance.SecurityGroups {
			fmt.Printf("  Security Group: %s (%s)\n", sg.Name, sg.ID)
			for _, port := range sg.PortsAccessible {
				fmt.Printf("    Port %d (%s):\n", port.Port, port.Protocol)
				fmt.Printf("      Inbound access allowed from: %v\n", port.SourceRanges)
			}
		}
		fmt.Println()
	}
}

// load config
func newSTSClient(ctx context.Context) *sts.Client {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Create and return STS client
	return sts.NewFromConfig(cfg)
}

func newEC2Client(ctx context.Context) *ec2.Client {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	return ec2.NewFromConfig(cfg)
}

func analyzeEc2Instances(ctx context.Context, ec2Client *ec2.Client) ([]Ec2Instance, error) {
	// Get all instances
	instances, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	var results []Ec2Instance

	// Collect all unique security group IDs
	securityGroupIDs := make([]string, 0, 10)
	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			for _, sg := range instance.SecurityGroups {
				securityGroupIDs = append(securityGroupIDs, *sg.GroupId)
			}
		}
	}

	// Get security group details
	sgDetails, err := getSecurityGroupDetails(ctx, ec2Client, securityGroupIDs)
	if err != nil {
		return nil, err
	}

	// Analyze each instance
	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			var instanceName string
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					instanceName = *tag.Value
					break
				}
			}

			access := Ec2Instance{
				ID:   *instance.InstanceId,
				Name: instanceName,
			}

			if instance.PublicIpAddress != nil {
				access.PublicIP = *instance.PublicIpAddress
			}

			// Analyze each security group attached to the instance
			for _, sg := range instance.SecurityGroups {
				if details, ok := sgDetails[*sg.GroupId]; ok {
					sgAccess := analyzeSecurityGroup(details)
					access.SecurityGroups = append(access.SecurityGroups, sgAccess)
				}
			}

			results = append(results, access)
		}
	}

	return results, nil
}

func getSecurityGroupDetails(ctx context.Context, ec2Client *ec2.Client, sgIDs []string) (map[string]types.SecurityGroup, error) {

	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: sgIDs,
	}

	result, err := ec2Client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	sgMap := make(map[string]types.SecurityGroup)
	for _, sg := range result.SecurityGroups {
		sgMap[*sg.GroupId] = sg
	}

	return sgMap, nil
}

func analyzeSecurityGroup(sg types.SecurityGroup) SecurityGroups {
	access := SecurityGroups{
		ID:   *sg.GroupId,
		Name: *sg.GroupName,
	}

	// Analyze inbound rules
	for _, rule := range sg.IpPermissions {
		portAccess := PortAccessible{
			Protocol: *rule.IpProtocol,
		}

		// Handle port ranges
		if rule.FromPort != nil {
			portAccess.Port = *rule.FromPort
		}

		// Collect IP ranges
		for _, ipRange := range rule.IpRanges {
			portAccess.SourceRanges = append(portAccess.SourceRanges, *ipRange.CidrIp)
		}

		access.PortsAccessible = append(access.PortsAccessible, portAccess)
	}

	return access
}
