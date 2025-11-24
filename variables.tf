variable "vpc_id" {
  default = "VPC ID of existing Virtual Private Cloud (VPC)."
  type    = string
}

variable "instance_type" {
  description = "Recommended instance types: m5n.xlarge for media forwarding; c5n.2xlarge or c5n.9xlarge for transcoding."
  type        = string
  default     = "m5.xlarge"
}

variable "ac_sbc_instance_profile_name" {
  description = "Name of existing IAM role that allows SBC to manage its IP addresses."
  type        = string
}

variable "ac_sbc_key" {
  description = "Name of existing Key Pair used for securing access to the SSH interface."
  type        = string
}

variable "ac_sbc_image_id" {
  description = "AMI ID of AudioCodes Mediant VE SBC image in specific region. Refer to Mediant VE offer in AWS marketplace - https://aws.amazon.com/marketplace/pp/prodview-lzov3dr64koi2 - to get correct AMI ID."
  type        = string
}
variable "ac_sbc_eth0_subnet_id" {
  description = "Subnet ID of existing Subnet in your VPC. Must provide access to the EC2 API endpoint via private IP addresses - refer to https://www.audiocodes.com/media/15887/mediant-virtual-edition-sbc-for-amazon-aws-installation-manual-ver-74.pdf for details. The subnet is used for HA traffic between two SBC instances and for accessing EC2 API during switchover. It is attached the the 1st network interface (eth0)."
  type        = string
}
variable "ac_sbc1_eth0_ip" {
  description = "Primary IP address for Active SBC interface (eth0)."
  type        = string
  default     = ""
}
variable "ac_sbc2_eth0_ip" {
  description = "Primary IP address for Stand-by SBC interface (eth0)."
  type        = string
  default     = ""
}

variable "ac_sbc_eth1_subnet_id" {
  description = "Subnet ID of existing Subnet in your VPC. The subnet may be used for Management traffic (HTTP, SSH). It is attached the the 2nd network interface (eth1)."
  type        = string
}
variable "ac_sbc_eth1_ip" {
  description = "Secondary Shared IP address for interface (eth1)"
  type        = string
  default     = ""
}
variable "ac_sbc1_eth1_ip" {
  description = "Primary IP address for Active SBC interface (eth1). Not used"
  type        = string
  default     = ""
}
variable "ac_sbc2_eth1_ip" {
  description = "Primary IP address for Stand-by SBC interface (eth1). Not used"
  type        = string
  default     = ""
}

variable "ac_sbc_eth2_subnet_id" {
  description = "Subnet ID of existing Subnet in your VPC. The subnet may be used for Internal VoIP traffic (SIP, RTP, RTCP)."
  type        = string
}
variable "ac_sbc_eth2_ip" {
  description = "Secondary Shared IP address for interface (eth2)"
  type        = string
  default     = ""
}
variable "ac_sbc1_eth2_ip" {
  description = "Primary IP address for Active SBC interface (eth2). Not used"
  type        = string
  default     = ""
}
variable "ac_sbc2_eth2_ip" {
  description = "Primary IP address for Stand-by SBC interface (eth2). Not used"
  type        = string
  default     = ""
}

variable "ac_sbc_eth3_subnet_id" {
  description = "Subnet ID of existing Subnet in your VPC. The subnet may be used for External (Outside) VoIP traffic (SIP, RTP, RTCP). It is attached the the 4th network interface (eth3)."
  type        = string
  default     = ""
}
variable "ac_sbc_eth3_ip" {
  description = "Secondary Shared IP address for interface (eth3)"
  type        = string
  default     = ""
}
variable "ac_sbc1_eth3_ip" {
  description = "Primary IP address for Active SBC interface (eth3). Not used"
  type        = string
  default     = ""
}
variable "ac_sbc2_eth3_ip" {
  description = "Primary IP address for Stand-by SBC interface (eth3). Not used"
  type        = string
  default     = ""
}

variable "ac_sbc_eth3_enable" {
  type    = bool
  default = false
}

variable "ac_sbc_eth3_public_enable" {
  description = "Switch to enable Public IP address attached to Interface eth3"
  type        = bool
  default     = false
}

variable "ac_sbc_eth3_public_ip" {
  description = "Reference to Public IP Address (EIP). Public IP is created outside of this module. If ac_sbc_eth3_public_enable is set to true, and ac_sbc_eth3_public_ip is not set, the EIP will be created automatically."
  type        = string
  default     = ""
}


# variable "ac_sbc_eth4_subnet_id" { type = string }
# variable "ac_sbc_eth4_ip" { type = string }
# variable "ac_sbc_eth4_enable" {
#   type    = bool
#   default = false
# }


variable "root_ebs" {
  type        = list(map(string))
  description = "Customize ebs volume"
  default = [{
    "volume_type" = "gp3"
    "volume_size" = 50
  }]
}

variable "tags" {
  type = map(string)
}


variable "ec2_name" {
  description = "Deafault SBC Name: sbc-01. Active Node Name Tag: sbc-01a, Standby Node Name Tag: sbc-01b"
  type        = string
  default     = "sbc-01"
}
variable "ec2_endpoint" {
  description = "HA Subnet needs VPC EC2 endpoint to access the AWS API"
  type        = string
  default     = ""
}

variable "voip_external_ingress_rules" {
  description = "List of ingress rules for Outisde VoIP Security Group"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_ipv4   = string
    description = string
  }))
  default = []
}

variable "voip_external_egress_rules" {
  description = "List of egress rules for Outisde VoIP Security Group"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_ipv4   = string
    description = string
  }))
  default = []
}
