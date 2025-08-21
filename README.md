{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListBucketForUser",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/NOME_DO_USER" },
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": "arn:aws:s3:::bucket-um"
    },
    {
      "Sid": "AllowPutObjectOnlyForUser",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/NOME_DO_USER" },
      "Action": [
        "s3:PutObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": "arn:aws:s3:::bucket-um/*"
    },
    {
      "Sid": "DenyGetObjectForUser",
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/NOME_DO_USER" },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::bucket-um/*"
    },
    {
      "Sid": "DenyInsecureTransportAll",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::bucket-um",
        "arn:aws:s3:::bucket-um/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
