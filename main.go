package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rds_types "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	args := os.Args
	fmt.Println("All arguments:", args)
	fmt.Println("Program name:", args[0])
	if len(args) > 1 {
		fmt.Println("First argument:", args[1])
	}

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
	// Create "database" (it's just a file as of Feb 25th, 2025)
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Scan for RDS instances across all regions
	fmt.Printf("Analyzing RDS databases across multiple regions for AWS Account: %s\n\n", *result.Account)
	databaseInstances := scanRDSInstancesAcrossRegions(ctx)

	fmt.Fprintf(file, "RDS Start\n")

	// Print all RDS instances found
	for region, instances := range databaseInstances {
		fmt.Fprintf(file, "Region: %s\n", region)
		if len(instances) == 0 {
			fmt.Fprintf(file, "  No RDS instances found\n")
			continue
		}

		for _, db := range instances {
			var databaseInfo string

			// Build the database information string
			if db.DBName != nil {
				databaseInfo = fmt.Sprintf("  DB: %s", *db.DBName)
			} else if db.DBInstanceIdentifier != nil {
				databaseInfo = fmt.Sprintf("  Instance: %s (no DB name)", *db.DBInstanceIdentifier)
			} else {
				databaseInfo = "  Unknown database"
			}

			// Add engine information if available
			if db.Engine != nil {
				databaseInfo += fmt.Sprintf(", Engine: %s", *db.Engine)
			}

			// Add status information if available
			if db.DBInstanceStatus != nil {
				databaseInfo += fmt.Sprintf(", Status: %s", *db.DBInstanceStatus)
			}

			fmt.Fprintf(file, "%s\n", databaseInfo)
		}
	}

	fmt.Fprintf(file, "RDS End\n")

	// Print instance results
	fmt.Fprintf(file, "Instance Report!\n")
	if len(args) > 1 && args[1] == "just-instances" {
		for _, instance := range instances {
			fmt.Fprintf(file, "Instance ID: %s\n", instance.ID)
			if instance.Name != "" {
				fmt.Fprintf(file, "Name: %s\n", instance.Name)
			} else {
				fmt.Fprintf(file, "Name: N/A\n")
			}
		}
	} else {
		for _, instance := range instances {
			fmt.Fprintf(file, "Instance ID: %s\n", instance.ID)
			if instance.Name != "" {
				fmt.Fprintf(file, "Name: %s\n", instance.Name)
			}
			if instance.PublicIP != "" {
				fmt.Fprintf(file, "Public IP: %s\n", instance.PublicIP)
			}

			fmt.Fprintln(file, "Security Groups:")
			for _, sg := range instance.SecurityGroups {
				fmt.Fprintf(file, "  Security Group: %s (%s)\n", sg.Name, sg.ID)
				for _, port := range sg.PortsAccessible {
					fmt.Fprintf(file, "    Port %d (%s):\n", port.Port, port.Protocol)
					fmt.Fprintf(file, "      Inbound access allowed from: %v\n", port.SourceRanges)
				}
			}
		}
	}
	fmt.Fprintf(file, "----------\n")

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	// Read the file content
	byteArray, err := os.ReadFile("output.txt")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		// Set the content type to text/html
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// Write a proper HTML response with formatting
		fmt.Fprintf(w, "<html><head><title>Automatic APT Results</title>")
		fmt.Fprintf(w, "<style>body{font-family:monospace;white-space:pre;padding:20px;line-height:1.5}</style>")
		fmt.Fprintf(w, "</head><body>")

		// Write the content with HTML encoding
		fmt.Fprintf(w, "%s", string(byteArray))
		fmt.Fprintf(w, "</body></html>")
	})

	http.ListenAndServe(":3000", r)
}

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

func newRDSClient(ctx context.Context) *rds.Client {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	return rds.NewFromConfig(cfg)
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

// scanRDSInstancesAcrossRegions scans for RDS instances across all specified regions
func scanRDSInstancesAcrossRegions(ctx context.Context) map[string][]rds_types.DBInstance {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	results := make(map[string][]rds_types.DBInstance)

	// Define regions to scan
	var awsRegions = []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1",
		// Add more regions as needed
	}

	// Scan each region in parallel
	for _, region := range awsRegions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()

			fmt.Printf("Scanning region %s for RDS instances...\n", region)
			instances, err := scanRDSInstancesInRegion(ctx, region)

			if err != nil {
				fmt.Printf("Error scanning region %s: %v\n", region, err)
				return
			}

			mutex.Lock()
			results[region] = instances
			mutex.Unlock()

			fmt.Printf("Found %d RDS instances in region %s\n", len(instances), region)
		}(region)
	}

	wg.Wait()
	return results
}

// scanRDSInstancesInRegion scans for RDS instances in a specific region
func scanRDSInstancesInRegion(ctx context.Context, region string) ([]rds_types.DBInstance, error) {
	// Create RDS client for the specific region
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for region %s: %w", region, err)
	}

	rdsClient := rds.NewFromConfig(cfg)

	// Get RDS instances
	databases, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		// Don't treat access denied errors as fatal, just return empty results
		if err.Error() == "AccessDenied" || err.Error() == "UnauthorizedOperation" {
			fmt.Printf("Access denied for RDS in region %s. Skipping...\n", region)
			return []rds_types.DBInstance{}, nil
		}
		return nil, fmt.Errorf("failed to describe DB instances in region %s: %w", region, err)
	}

	return databases.DBInstances, nil
}
