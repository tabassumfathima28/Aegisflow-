terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
}
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------
# NETWORKING: A small isolated VPC so we don't touch your
# existing AWS setup at all.
# ---------------------------------------------------------

resource "aws_vpc" "aegisflow_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.aegisflow_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.aegisflow_vpc.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.aegisflow_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# ---------------------------------------------------------
# SECURITY GROUPS
# "Compromised" = wide open, simulating a badly configured
# production server. "Isolated" = a lockdown group with zero
# rules, used for quarantine after detection.
# ---------------------------------------------------------

resource "aws_security_group" "compromised_sg" {
  name        = "${var.project_name}-compromised-sg"
  description = "Wide-open SG simulating an exposed production server"
  vpc_id      = aws_vpc.aegisflow_vpc.id

  ingress {
    description = "Allow HTTP from anywhere (intentionally insecure for the lab)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow SSH from anywhere (intentionally insecure for the lab)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name  = "${var.project_name}-compromised-sg"
    State = "Normal-Operation"
  }
}

resource "aws_security_group" "isolated_sg" {
  name        = "${var.project_name}-isolated-sg"
  description = "Zero-rule quarantine SG: no inbound, no outbound"
  vpc_id      = aws_vpc.aegisflow_vpc.id

  # Intentionally no ingress or egress blocks = deny everything.

  tags = {
    Name  = "${var.project_name}-isolated-sg"
    State = "Quarantine"
  }
}

# ---------------------------------------------------------
# MOCK VICTIM SERVER
# A tiny EC2 instance running a simple webpage, so you have
# something visible to prove containment worked (page goes
# from reachable -> unreachable).
# ---------------------------------------------------------

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "victim_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.compromised_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              yum install -y httpd
              systemctl enable httpd
              systemctl start httpd
              echo "<h1>Welcome to AegisFlow Mock Production Server!</h1>" > /var/www/html/index.html
              EOF

  tags = {
    Name  = "${var.project_name}-victim-server"
    State = "Normal-Operation"
  }
}
