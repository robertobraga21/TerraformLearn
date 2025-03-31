terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "us-east-1"
}

# Busca o security group existente pelo nome "devops-4"
data "aws_security_group" "devops_4" {
  name = "devops-4"  # Nome exato do security group
}

resource "aws_instance" "app_server" {
  ami           = "ami-084568db4383264d4"
  instance_type = "t2.micro"
  key_name = "test-key"
  vpc_security_group_ids = [data.aws_security_group.devops_4.id]  # ID do SG "devops-4"
  user_data = <<-EOF
                 #!/bin/bash
                 cd /home/ubuntu
                 echo "<h1>Feito com Terraform</h1>" > index.html
                 nohup busybox httpd -f -p 8080 &
                 EOF

  tags = {
    Name = "Teste WebServer"
  }
}