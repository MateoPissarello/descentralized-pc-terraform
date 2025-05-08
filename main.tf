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

resource "aws_s3_bucket" "input_bucket" {
  bucket        = "decentralized-file-input"
  force_destroy = true
}

resource "aws_s3_bucket" "parts_bucket" {
  bucket        = "decentralized-parts"
  force_destroy = true
}

resource "aws_s3_bucket" "encrypted_output_bucket" {
  bucket        = "decentralized-encrypted-output"
  force_destroy = true
}

resource "aws_s3_bucket" "encrypted_parts_bucket" {
  bucket        = "decentralized-encrypted-parts-output"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "encrypted_parts_block" {
  bucket = aws_s3_bucket.encrypted_parts_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "encrypted_output_block" {
  bucket = aws_s3_bucket.encrypted_output_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "parts_block" {
  bucket = aws_s3_bucket.parts_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "input_block" {
  bucket                  = aws_s3_bucket.input_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda-encryption-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "lambda_s3_access" {
  name = "lambda-s3-access-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Effect = "Allow",
        Resource = [
          "${aws_s3_bucket.input_bucket.arn}/*",
          "${aws_s3_bucket.parts_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_s3_policy_attachment" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_s3_access.arn
}

resource "aws_lambda_function" "split_file_lambda" {
  function_name    = "split-file-lambda"
  role             = aws_iam_role.lambda_exec_role.arn
  runtime          = "python3.10"
  handler          = "lambda_function.lambda_handler"
  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip")

  environment {
    variables = {
      OUTPUT_BUCKET = aws_s3_bucket.parts_bucket.bucket
      SQS_QUEUE_URL = aws_sqs_queue.encryption_queue.id
    }
  }
}

resource "aws_s3_bucket_notification" "trigger_lambda" {
  bucket = aws_s3_bucket.input_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.split_file_lambda.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}

# Lambda permission to allow S3 to invoke the Lambda function
resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.split_file_lambda.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.input_bucket.arn
}

# SQS Queue for encryption parts
resource "aws_sqs_queue" "encryption_queue" {
  name = "encryption-parts-queue"
}

resource "aws_iam_policy" "lambda_sqs_send_policy" {
  name = "lambda-sqs-send-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "sqs:SendMessage",
        Resource = aws_sqs_queue.encryption_queue.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_sqs_policy_attachment" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_sqs_send_policy.arn
}

# VPC con 3 subredes públicas, una en cada AZ
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "decentralized-encryption-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "encryption-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "encryption-public-rt"
  }
}

# Subredes públicas en 3 AZ distintas (us-east-1a, 1b, 1c)
locals {
  azs = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet("10.0.0.0/16", 4, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${local.azs[count.index]}"
  }
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Security Group para EC2 (SSH y acceso a internet)
resource "aws_security_group" "ec2_sg" {
  name        = "ec2-encryption-sg"
  description = "Allow SSH and outbound internet access"
  vpc_id      = aws_vpc.main.id

  ingress {
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
    Name = "ec2-encryption-sg"
  }
}

# Key pair (asegúrate de que este key_name exista en tu cuenta o créalo antes)
variable "key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "decentralized_pc"
}

# AMI Amazon Linux 2 (para us-east-1)
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Crear un EFS compartido
resource "aws_efs_file_system" "shared" {
  creation_token = "efs-encryption-shared"
  tags = {
    Name = "encryption-efs"
  }
}

# Grupo de seguridad mejorado para EFS
resource "aws_security_group" "efs_sg" {
  name        = "efs-sg"
  description = "Allow NFS traffic from EC2 instances"
  vpc_id      = aws_vpc.main.id

  # Permitir NFS desde el grupo de seguridad de EC2
  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
    description     = "NFS from EC2 instances"
  }

  # Permitir NFS desde todo el VPC
  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "NFS from VPC CIDR"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "efs-sg"
  }
}

resource "aws_efs_mount_target" "efs_mount" {
  count           = 3
  file_system_id  = aws_efs_file_system.shared.id
  subnet_id       = aws_subnet.public[count.index].id
  security_groups = [aws_security_group.efs_sg.id]
}

resource "aws_dynamodb_table" "encryption_status" {
  name         = "EncryptionStatus"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "original_file"
  range_key    = "part_number"

  attribute {
    name = "original_file"
    type = "S"
  }

  attribute {
    name = "part_number"
    type = "N"
  }

  tags = {
    Name = "Encryption Coordination Table"
  }
}

resource "aws_iam_role" "ec2_encryption_role" {
  name = "ec2-encryption-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}


resource "aws_iam_role_policy_attachment" "ec2_encryption_policy_attach" {
  role       = aws_iam_role.ec2_encryption_role.name
  policy_arn = aws_iam_policy.ec2_encryption_policy.arn
}

variable "kms_key_arn" {
  type        = string
  description = "ARN de la clave KMS utilizada para cifrar/descifrar"
  default     = "arn:aws:kms:us-east-1:225989373192:key/44573c5c-8f60-43b6-a4ae-663e3990866f"
}

# Política IAM mejorada para EC2
resource "aws_iam_policy" "ec2_encryption_policy" {
  name = "ec2-encryption-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ],
        Resource = aws_dynamodb_table.encryption_status.arn
      },
      {
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        Resource = var.kms_key_arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      },
      # Permisos para SQS
      {
        Effect = "Allow",
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ],
        Resource = aws_sqs_queue.encryption_queue.arn
      },
      # Permisos para S3
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.input_bucket.arn,
          "${aws_s3_bucket.input_bucket.arn}/*",
          aws_s3_bucket.parts_bucket.arn,
          "${aws_s3_bucket.parts_bucket.arn}/*",
          aws_s3_bucket.encrypted_output_bucket.arn,
          "${aws_s3_bucket.encrypted_output_bucket.arn}/*",
          aws_s3_bucket.encrypted_parts_bucket.arn,
          "${aws_s3_bucket.encrypted_parts_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Crear tres instancias EC2
resource "aws_instance" "ec2_node_1" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public[0].id
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_encryption_profile.name
  user_data = templatefile("${path.module}/encryption_user_data.sh", {
    SQS_QUEUE_URL           = aws_sqs_queue.encryption_queue.id,
    INPUT_BUCKET            = aws_s3_bucket.input_bucket.id,
    PARTS_BUCKET            = aws_s3_bucket.parts_bucket.id,
    ENCRYPTED_PARTS_BUCKET  = aws_s3_bucket.encrypted_parts_bucket.id,
    ENCRYPTED_OUTPUT_BUCKET = aws_s3_bucket.encrypted_output_bucket.id,
    KMS_KEY_ID              = var.kms_key_arn,
    DYNAMO_TABLE            = aws_dynamodb_table.encryption_status.id,
    EFS_ID                  = aws_efs_file_system.shared.id

  })
  depends_on = [aws_efs_mount_target.efs_mount[0], aws_efs_mount_target.efs_mount[1], aws_efs_mount_target.efs_mount[2]]

  tags = {
    Name = "Encryptor-Node-1"
  }

  # Esperar a que la instancia esté disponible antes de continuar
  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${self.id} --region us-east-1"
  }

}

resource "aws_instance" "ec2_node_2" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public[1].id
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_encryption_profile.name
  user_data = templatefile("${path.module}/encryption_user_data.sh", {
    SQS_QUEUE_URL           = aws_sqs_queue.encryption_queue.id,
    INPUT_BUCKET            = aws_s3_bucket.input_bucket.id,
    PARTS_BUCKET            = aws_s3_bucket.parts_bucket.id,
    ENCRYPTED_PARTS_BUCKET  = aws_s3_bucket.encrypted_parts_bucket.id,
    ENCRYPTED_OUTPUT_BUCKET = aws_s3_bucket.encrypted_output_bucket.id,
    KMS_KEY_ID              = var.kms_key_arn,
    DYNAMO_TABLE            = aws_dynamodb_table.encryption_status.id,
    EFS_ID                  = aws_efs_file_system.shared.id

  })
  depends_on = [aws_efs_mount_target.efs_mount[0], aws_efs_mount_target.efs_mount[1], aws_efs_mount_target.efs_mount[2]]

  tags = {
    Name = "Encryptor-Node-2"
  }

  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${self.id} --region us-east-1"
  }

}

resource "aws_instance" "ec2_node_3" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public[2].id
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_encryption_profile.name
  user_data = templatefile("${path.module}/encryption_user_data.sh", {
    SQS_QUEUE_URL           = aws_sqs_queue.encryption_queue.id,
    INPUT_BUCKET            = aws_s3_bucket.input_bucket.id,
    PARTS_BUCKET            = aws_s3_bucket.parts_bucket.id,
    ENCRYPTED_PARTS_BUCKET  = aws_s3_bucket.encrypted_parts_bucket.id,
    ENCRYPTED_OUTPUT_BUCKET = aws_s3_bucket.encrypted_output_bucket.id,
    KMS_KEY_ID              = var.kms_key_arn,
    DYNAMO_TABLE            = aws_dynamodb_table.encryption_status.id,
    EFS_ID                  = aws_efs_file_system.shared.id

  })
  depends_on = [aws_efs_mount_target.efs_mount[0], aws_efs_mount_target.efs_mount[1], aws_efs_mount_target.efs_mount[2]]

  tags = {
    Name = "Encryptor-Node-3"
  }

  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${self.id} --region us-east-1"
  }

}

resource "aws_iam_instance_profile" "ec2_encryption_profile" {
  name = "ec2-encryption-profile"
  role = aws_iam_role.ec2_encryption_role.name
}

# Outputs para facilitar depuración
output "efs_dns_name" {
  value       = aws_efs_file_system.shared.dns_name
  description = "DNS name for the EFS file system"
}

output "ec2_instance_ips" {
  value = {
    node1 = aws_instance.ec2_node_1.public_ip
    node2 = aws_instance.ec2_node_2.public_ip
    node3 = aws_instance.ec2_node_3.public_ip
  }
  description = "Public IPs of the EC2 instances"
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.encryption_queue.id
  description = "URL of the SQS queue"
}

output "s3_input_bucket" {
  value       = aws_s3_bucket.input_bucket.bucket
  description = "Name of the S3 input bucket"
}

output "s3_parts_bucket" {
  value       = aws_s3_bucket.parts_bucket.bucket
  description = "Name of the S3 parts bucket"
}

output "s3_encrypted_output_bucket" {
  value       = aws_s3_bucket.encrypted_output_bucket.bucket
  description = "Name of the S3 encrypted output bucket"
}
output "s3_encrypted_parts_bucket" {
  value       = aws_s3_bucket.encrypted_parts_bucket.bucket
  description = "Name of the S3 encrypted parts bucket"
}

