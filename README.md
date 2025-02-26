# Automatic APT
NIST [defines](https://csrc.nist.gov/glossary/term/advanced_persistent_threat) an APT as "An adversary with sophisticated levels of expertise and significant resources, allowing it through the use of multiple different attack vectors (e.g., cyber, physical, and deception), to generate opportunities to achieve its objectives which are typically to establish and extend its presence within the information technology infrastructure of organizations for purposes of continually exfiltrating information and/or to undermine or impede critical aspects of a mission, program, or organization, or place itself in a position to do so in the future; moreover, the advanced persistent threat pursues its objectives repeatedly over an extended period of time, adapting to a defender’s efforts to resist it, and with determination to maintain the level of interaction needed to execute its objectives."

Automatic APT (automatic-APT) is a program that runs in your AWS environment to tell you your biggest exposure risks and vulnerabilities.

## Capabilities
This app lists your RDS databases.

## Usage
Run `go run main.go` after configuring your AWS credentials on the command-line. Then, navigate to localhost:3000. It will list and describe all of the security groups you have configured on your EC2 instances.

## Command-line Options
- `go run main.go just-instances` will show just the instance IDs and names -- no security group details.

## Roadmap (Hopefully)
- API Sec capabilities
- K8s capabilities
- Container capabilities
