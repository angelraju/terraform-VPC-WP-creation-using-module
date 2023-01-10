variable "project" {
  default     = "demo-test"
  description = "project name"
}
 
 
variable "environment" {}
 
variable "vpc_cidr" {}
 
 
locals {
  subnets = length(data.aws_availability_zones.available.names)
}

variable "enable_nat_gateway"{
type = bool
default = true
}
