# Deploying RemediGenius-CE

Two supported paths:

| Path | What it is | Guide |
| --- | --- | --- |
| `aws-single` | The community install: one `terraform apply` provisions the S3 bucket, Glue database, IAM roles, security group and a disposable Spot instance on plain AL2023. | [aws-single/README.md](aws-single/README.md) |
| `workstation` | A Docker image for trying the desk on your own machine. | [../docs/WORKSTATION.md](../docs/WORKSTATION.md) |

`aws-single` is the published, tested path: it provisions everything in one root and restores itself from S3 if the
instance is replaced. See the [aws-single guide](aws-single/README.md) for variables, IAM boundaries and recovery.
