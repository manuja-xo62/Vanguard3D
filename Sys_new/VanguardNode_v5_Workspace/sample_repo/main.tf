resource "aws_s3_bucket" "vanguard_demo_bucket" {
  replication_configuration {
    role = "arn:aws:iam::123456789012:role/tf-iam-role-replication-12345"
    rules {
      status = "Enabled"
    }
  } # [VANGUARD NANO-PATCH APPLIED]
  logging {
    target_bucket = "logging-bucket"
    target_prefix = "log/"
  } # [VANGUARD NANO-PATCH APPLIED]
  bucket = "vanguard-public-data"
}

resource "aws_s3_bucket_acl" "vanguard_demo_acl" {
  bucket = aws_s3_bucket.vanguard_demo_bucket.id
  acl    = "public-read"
}