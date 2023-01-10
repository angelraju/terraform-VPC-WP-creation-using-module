# terraform-VPC-WP-creation-using-module
### Description.
Terraform is a code tool that lets you define both cloud and on-prem resources in human-readable configuration files that you can version, reuse, and share.

Here im going to present on how to use Terraform to build an AWS VPC by calling it as a module and along with here we creating private/public Subnet and Network Gateway's for the VPC. Therefore, 3 Private and 3 Public, 1 NAT Gateways, 1 Internet Gateway, and 2 Route Tables. Also we are designing 3 EC2 instances, one as bastion, frontend-webserver and another as database server along with its respective security groups.

Beside we are using terraform to provision infrastructure. we are creating following aws resources for this such as;

 -  VPC 
- Subnets -  we need three public and three private subnets based on the avaiablity zones in that region. 
- Route Tables -  here we are using both  private and public  route tables for public and private subnets
- Internet Gateway
- Nat Gateway - used to  provide internet connectivity for instances under private network. That should be define as condition and if required it will create.

- Route table association - two table asscoiation needed for private as well as public

- EC2 instance
1. Frontend-webserver
2. Bastion server
3. DB-backend server
- EIP for NAT Gateway - it should b also depend on conditon given to NAT-gateway and according to this it will create.

- Security Groups to access EC2

1. Frontend-server Security Group;

allows SSH traffic from Bastion server/from a prefix-list and HTTP/S traffic from internet.

2. Bastion-server Security Group;

This security group allows inbound SSH traffic

3. Backend-server Security Group;

It allows the SSH connection originates Bastion server/from a prefix-list security group and MySQL connection originates from Frontend-server security group.

- AWS Keypair 

- AWS Route53 - here we use both Public & Private Hosted Zone to create DNS records for Backend server and Frontend server

### Pre-requisites:

1. IAM Role (Role needs to be attached on terraform running server)
2. knowledge about AWS services especially VPC, EC2 and IP Subnetting.
3. Terraform and its installation.

Installation steps:
```
wget https://releases.hashicorp.com/terraform/1.3.7/terraform_1.3.7_linux_amd64.zip
unzip terraform_1.3.7_linux_amd64.zip
mv terraform /usr/bin/
which terraform 
/usr/bin/terraform
```
## Steps required for the creation of this project;

### 1. Steps for creating the VPC module:

module path can be choose as we wish here I take "/var/vpc-module". Inside this directory module .tf files are stored. I have separated the code into multiple .tf files and that is a best practice to follow.

>  configure datasource.tf file;
 ```
 data "aws_availability_zones" "available" {
  state = "available"
}
```
> content of main.tf file for creating VPC
```
-------------------------------------------------------------------
 Vpc Creation
-------------------------------------------------------------------

resource "aws_vpc" "vpc" {

  cidr_block       =  var.vpc_cidr
  instance_tenancy = "default"
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.project}-${var.environment}"
  }
}

-------------------------------------------------------------------
 Interner-gateway creation
-------------------------------------------------------------------

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.project}-${var.environment}"
  }
}

-------------------------------------------------------------------
Public Subnet
-------------------------------------------------------------------

resource "aws_subnet" "public" {
    
  count      = local.subnets  
  vpc_id     = aws_vpc.vpc.id
  cidr_block = cidrsubnet(var.vpc_cidr,4,count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project}-${var.environment}-public${count.index + 1}"
  }
}

-------------------------------------------------------------------
Private Subnet
-------------------------------------------------------------------

resource "aws_subnet" "private" {

  count      = local.subnets 
  vpc_id     = aws_vpc.vpc.id
  cidr_block = cidrsubnet(var.vpc_cidr,4,"${local.subnets + count.index}")
  availability_zone = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.project}-${var.environment}-private${count.index + 1}"
  }

}

-------------------------------------------------------------------
Elastic IP
-------------------------------------------------------------------

resource "aws_eip" "nat" {
 count = var.enable_nat_gateway ? 1 : 0
 vpc      = true
  tags = {
    Name = "${var.project}-${var.environment}-natgw"
  }
}

-------------------------------------------------------------------
 NAT-gateway Creation
-------------------------------------------------------------------

resource "aws_nat_gateway" "nat" {
  
  count = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat.0.id
  subnet_id     = aws_subnet.public[0].id
  tags = {
    Name = "${var.project}-${var.environment}"
  }
  depends_on = [aws_internet_gateway.igw]
}

-------------------------------------------------------------------
Public Route-table
-------------------------------------------------------------------

resource "aws_route_table" "public" {

  vpc_id = aws_vpc.vpc.id
  route {
  cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${var.project}-${var.environment}-public"
  }

}

-------------------------------------------------------------------
Private Route-table
-------------------------------------------------------------------
resource "aws_route_table" "private" {

  vpc_id = aws_vpc.vpc.id
  
  tags = {
   Name = "${var.project}-${var.environment}-private"
  }
}

------------------------------------------------------------------------------
Route entry for private route-table based on a condition related to NAT-gateway
------------------------------------------------------------------------------

 resource "aws_route" "enable_nat" {
  
  count                     = var.enable_nat_gateway ? 1 : 0
  route_table_id            = aws_route_table.private.id
  destination_cidr_block    = "0.0.0.0/0"     
  nat_gateway_id            = aws_nat_gateway.nat.0.id
  depends_on                = [aws_route_table.private]
  }
  
-------------------------------------------------------------------
Public-Route-table association
-------------------------------------------------------------------

resource "aws_route_table_association" "public" {
  count          = local.subnets 
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

-------------------------------------------------------------------
Private-Route-table association
-------------------------------------------------------------------

resource "aws_route_table_association" "private" {
  count          = local.subnets 
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
```

> configure variable.tf file

Input variables that are passed as arguments should be declared as variables in the variables.tf file

~~~
variable "project" {
  default     = "demo-test"
  description = "project name"
}
 
 
variable "environment" {}
 
variable "vpc_cidr" {}
 
 
locals {
  subnets = length(data.aws_availability_zones.available.names)
}

#### NAT-gateway will be enabled based on this Boolean value

variable "enable_nat_gateway"{
type = bool
default = true
}
~~~
> output.tf file

~~~
output "vpc_id"{
 value = aws_vpc.vpc.id
}
output "public_subnets" { 
 value = aws_subnet.public[*].id
}

output "private_subnets" {
 value = aws_subnet.private[*].id
}
~~~

Here we completing the creation of VPC and now we have to crate EC2, Security,groups using the above VPC module;

### 2. Steps for creating EC2,Security groups using the VPC module:

> main.tf file 

AWS resources used here;

1. Prefix list - A Prefix List is a collection of CIDR blocks that can be used to configure VPC security groups, VPC route tables etc.
2. security group for bastion,frontend and backend server
3. AWS instance
4. Route53 entry


```

--------------------------------------------------------------------
Calling Module
 --------------------------------------------------------------------

module "vpc" {
  source      = "/var/vpc-module/"
  project     = var.project
  environment = var.environment
  vpc_cidr    = var.vpc_cidr
}


--------------------------------------------------------------------
Creating prefix-list from a list of public IP
 --------------------------------------------------------------------

resource "aws_ec2_managed_prefix_list" "prefix" {
  name           = "${var.project}-${var.environment}-prefix"
  address_family = "IPv4"
  max_entries    = length(var.public_ips)

  dynamic "entry" {
    iterator = public-ip
    for_each = var.public_ips
    content {
      cidr = public-ip.value
    }
  }
  tags = {
    Name = "${var.project}-${var.environment}-prefix"
  }
}

--------------------------------------------------------------------
Creating SecurityGroup bastion
--------------------------------------------------------------------

resource "aws_security_group" "bastion-traffic" {
  name_prefix = "${var.project}-${var.environment}-bastion-"
  description = "Allows ssh traffic from prefix list"
  vpc_id      = module.vpc.vpc_id

  ingress {

    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.prefix.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project}-${var.environment}-bastion"
  }

  lifecycle {
    create_before_destroy = true
  }
}

--------------------------------------------------------------------
Creating SecurityGroup frontend
--------------------------------------------------------------------
 
resource "aws_security_group" "frontend-traffic" {
  name_prefix = "${var.project}-${var.environment}-frontend-"
  description = "Allow ssh , public_ports_frontend traffic"
  vpc_id      = module.vpc.vpc_id

  dynamic "ingress" {
    for_each = toset(var.public_ports_frontend)
    iterator = port
    content {

      from_port        = port.value
      to_port          = port.value
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  }

  ingress {

    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = var.ssh_to_frontend == true ? ["0.0.0.0/0"] : null
    security_groups = [aws_security_group.bastion-traffic.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project}-${var.environment}-frontend"
  }
  lifecycle {
    create_before_destroy = true
  }

}

--------------------------------------------------------------------
Creating SecurityGroup backend
 --------------------------------------------------------------------
 
resource "aws_security_group" "backend-traffic" {
  name_prefix = "${var.project}-${var.environment}-backend-"
  description = "Allow mysql,ssh traffic only"
  vpc_id      = module.vpc.vpc_id

  ingress {

    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend-traffic.id]
  }
  ingress {

    from_port       = var.bastion_port
    to_port         = var.bastion_port
    protocol        = "tcp"
    cidr_blocks     = var.ssh_to_backend == true ? ["0.0.0.0/0"] : null
    security_groups = [aws_security_group.bastion-traffic.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project}-${var.environment}-backend"
  }

  lifecycle {
    create_before_destroy = true
  }
}

=========================================================================
Creating SSH KeyPair
=========================================================================

resource "tls_private_key" "key_data" {
  algorithm = "RSA"
  rsa_bits  = 4096
}


resource "aws_key_pair" "ssh_key" {

  key_name_prefix  = "${var.project}-${var.environment}-"  
  public_key = tls_private_key.key_data.public_key_openssh

  provisioner "local-exec" {
    command = "echo '${tls_private_key.key_data.private_key_pem}' > ./test.pem ; chmod 400 ./test.pem"
  }
  }

--------------------------------------------------------------------
 Creating Bastion Instance
--------------------------------------------------------------------

resource "aws_instance" "bastion" {

  ami           = var.instance_ami
  instance_type = var.instance_type
  key_name      = aws_key_pair.ssh_key.key_name
  subnet_id     = module.vpc.public_subnets.1

  vpc_security_group_ids = [aws_security_group.bastion-traffic.id]

  tags = {

    "Name" = "${var.project}-${var.environment}-bastion"
  }
}

--------------------------------------------------------------------
 Creating Frontend Instance
 --------------------------------------------------------------------

resource "aws_instance" "frontend" {

  ami                         = var.instance_ami
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.ssh_key.key_name
  subnet_id                   = module.vpc.public_subnets.0
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.frontend-traffic.id]
  user_data                   = data.template_file.userdata2.rendered
  user_data_replace_on_change = true
  depends_on                  = [aws_instance.backend]

  tags = {

    "Name" = "${var.project}-${var.environment}-frontend"
  }
}

--------------------------------------------------------------------
 Creating Backend Instance
 --------------------------------------------------------------------
 
resource "aws_instance" "backend" {

  ami                         = var.instance_ami
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.ssh_key.key_name
  subnet_id                   = module.vpc.private_subnets.0
  associate_public_ip_address = false
  user_data                   = data.template_file.userdata1.rendered
  user_data_replace_on_change = true
  vpc_security_group_ids      = [aws_security_group.backend-traffic.id]

  # To ensure proper ordering, it is recommended to add an explicit dependency
  depends_on = [module.vpc.nat]
  
 tags = {

    "Name" = "${var.project}-${var.environment}-backend"
  }
}

--------------------------------------------------------------------
 Creating private route53 zone 
 --------------------------------------------------------------------
 
resource "aws_route53_zone" "private" {
  name = var.private_domain

  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

--------------------------------------------------------------------
 Creating a route53 A record to backend private IP
 --------------------------------------------------------------------

resource "aws_route53_record" "db_a" {
  zone_id = aws_route53_zone.private.zone_id

  name    = "db.${var.private_domain}"
  type    = "A"
  ttl     = "30"
  records = [aws_instance.backend.private_ip]
}

--------------------------------------------------------------------
 Creating a route53 A record to frontend public IP
 --------------------------------------------------------------------
 
resource "aws_route53_record" "wordpress" {
  zone_id = data.aws_route53_zone.mydomain.zone_id
  name    = "wordpress.${var.public_domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.frontend.public_ip]
}
````
> creating variables.tf file 

~~~
variable "project" {
  default     = "zomato"
  description = "project name"
}


variable "environment" {
  default     = "production"
  description = "project environemnt"
}


variable "region" {
  default = "ap-south-1"
}

variable "access_key" {
  default = "xxxxxxxxxxxxxxxxx"
}

variable "secret_key" {
  default = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}

variable "vpc_cidr" {
  default = "172.16.0.0/16"

}


variable "instance_ami" {

  default = "ami-0cca134ec43cf708f"
}

variable "instance_type" {

  default = "t2.micro"
}

##prefix-list

*==variables used to declare the prefix_list here you can add the public IP that need access to the SSH server==*

variable "public_ips" {
  type = list(string)
  default = [

    "103.148.21.111/32",
    "1.1.1.1/32",
    "2.2.2.2/32",
    "3.3.3.3/32",
    "4.4.4.4/32",
    "5.5.5.5/32"
  ]
}

*==here declares the ports for the frontend instance ==*

variable "public_ports_frontend" {
  type    = list(string)
  default = ["80", "443", "8080"]
}

*== by changing the value to true you can acces the frontend-webserver publically==*

variable "ssh_to_frontend" {
  default = "false"
}

*== by changing the value to true you can accees the server anywhere from the public ==*

variable "ssh_to_backend" {
  default = "false"
}

*==here declares the ports for the database instance ==*

variable "db_port" {
  default = "3306"
}

*==here declares the ports for the bastion instance ==*

variable "bastion_port" {
  default = "22"
}

*==here declares databse details required to install wordpress ==*

variable "root_password" {
  default = "xxxxxx"
}

variable "db_name" {
  default = "wpdb"
}

variable "db_user" {
  default = "wpdbuser"
}

variable "db_password" {
  default = "xxxxxx"
}

locals {

  db_host = "db.${var.private_domain}"
}

variable "private_domain" {
  default = "angeldevops.local"
}

variable "public_domain" {
  default = "domain.name"
}

locals {

  subnets = length(data.aws_availability_zones.available.names)

}
~~~
> creating output.tf file

```
output "vpc-module-return" {
  value = module.vpc
}

output "site_url" {
  value = "http://wordpress.${var.public_domain}"
}

output "userdata1" {
  value = data.template_file.userdata1.rendered
}

output "userdata2" {
  value = data.template_file.userdata2.rendered
}
```

> Creating userdata files for the three instances as separate files in project-directory

1. setup_frontend.sh [for frontend-ebserver]

```
#!/bin/bash
 
        echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
        echo "LANG=en_US.utf-8" >> /etc/environment
        echo "LC_ALL=en_US.utf-8" >> /etc/environment
        service sshd restart
        hostnamectl set-hostname frontend
        amazon-linux-extras install php7.4 

        yum install httpd -y

        systemctl restart httpd
        systemctl enable httpd

        wget https://wordpress.org/latest.zip
        unzip latest.zip
        cp -rf wordpress/* /var/www/html/
        mv /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
        chown -R apache:apache /var/www/html/*
        cd  /var/www/html/
        sed -i 's/database_name_here/${DB_NAME}/g' wp-config.php
        sed -i 's/username_here/${DB_USER}/g' wp-config.php
        sed -i 's/password_here/${DB_PASSWORD}/g' wp-config.php
        sed -i 's/localhost/${DB_HOST}/g' wp-config.php
```

2. setup_backend.sh

```
#!/bin/bash
 
        echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
        echo "LANG=en_US.utf-8" >> /etc/environment
        echo "LC_ALL=en_US.utf-8" >> /etc/environment
        service sshd restart
        hostnamectl set-hostname backend
        amazon-linux-extras install php7.4 -y
        rm -rf /var/lib/mysql/*
        yum remove mysql -y

        yum install httpd mariadb-server -y
        systemctl restart mariadb.service
        systemctl enable mariadb.service
        
        mysqladmin -u root password '${DB_ROOT}'
        mysql -u root -p${DB_ROOT} -e "create database ${DB_NAME};"
        mysql -u root -p${DB_ROOT} -e "create user '${DB_USER}'@'%' identified by '${DB_PASSWORD}';"
        mysql -u root -p${DB_ROOT} -e "grant all privileges on ${DB_NAME}.* to '${DB_USER}'@'%'"
        mysql -u root -p${DB_ROOT} -e "flush privileges"
```
 ### 3.  To Initialize

>cd /to/your/project/root/parent/directory
>terraform init
>terraform validate
>terraform plan
>terraform apply

2. To terminate

When you are all done remove all the created resources using

>terraform destroy

### Conclusion

The terraform module allows you to group resources together and reuse this group later, possibly many times. In this section, we have created a VPC by calling as module and launched the EC2 on the newly created VPC and isntalled WP based on it.
