resource "aws_s3_bucket" "vanguard_demo_bucket" {
  bucket = "vanguard-public-data"
}

resource "aws_s3_bucket_acl" "vanguard_demo_acl" {
  bucket = aws_s3_bucket.vanguard_demo_bucket.id
  acl    = "public-read"
}