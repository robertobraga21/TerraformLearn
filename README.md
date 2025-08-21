{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BucketLevelList",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:ListBucketMultipartUploads",
        "s3:ListBucketVersions"
      ],
      "Resource": [
        "arn:aws:s3:::bucket-um",
        "arn:aws:s3:::bucket-dois"
      ]
    },
    {
      "Sid": "ObjectLevelPutOnly",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": [
        "arn:aws:s3:::bucket-um/*",
        "arn:aws:s3:::bucket-dois/*"
      ]
    }
  ]
}
