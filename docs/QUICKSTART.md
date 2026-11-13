# Quickstart

Get RemediGenius-CE running and look at your first attention board. Pick the path that matches you. If you're
new, start with the Docker workstation — it's the lowest-friction first run and nothing is deployed into AWS.

| You are… | Path | Rough time |
| --- | --- | --- |
| New, just want to see it work | [Docker workstation](#path-1-docker-workstation-start-here) | ~15 min |
| Already running Hermes 0.23.1 | [Existing Hermes](#path-2-existing-hermes) | ~10 min |
| Want an always-on desk in your AWS account | [AWS Spot](#path-3-aws-spot) | ~30 min |

Every path needs the same three things:

1. **An AWS account with findings.** CE reads Security Hub, GuardDuty, Inspector, IAM Access Analyzer, Config,
   CloudWatch alarms and Health. It ranks what those services already report — it adds no detectors of its own.
2. **Read-only AWS access.** You'll create a read-only role below. CE never writes to your AWS.
3. **A model API key** for an OpenAI-compatible endpoint. The desk can scan without a model, but it can't chat.

One operator, one organization per installation. Findings, identifiers, IaC excerpts and chat go to the model
provider you configure — see [DATA-FLOW.md](DATA-FLOW.md) before connecting a production estate.

---

## Path 1: Docker workstation (start here)

Two containers run on your machine: a **desk** (the only place AWS credentials exist) and **Hermes** (the agent,
which gets no AWS credentials). Durable state lives in a folder on your machine, `~/RemediGenius-CE`.

### 1. Prerequisites

- Docker — Docker Desktop on Windows/macOS, or Docker Engine on Linux — running.
- Python 3.11+ with boto3: `python -m pip install boto3`
- AWS CLI with a configured profile. Check it: `aws sts get-caller-identity --profile <profile>`
- A model API key (OpenAI-compatible endpoint).

### 2. Create a read-only role — the security step, don't skip it

The workstation should assume a **read-only role**, not use your everyday credentials. This keeps long-lived or
admin keys out of the container entirely. You need permission to create an IAM role (or ask your administrator).

```sh
# 1. Note your identity's Arn — this is what will assume the role
aws sts get-caller-identity --profile <profile>

# 2. Create a read-only role that identity can assume (replace <YOUR_ARN>)
aws iam create-role --role-name RemediGeniusReadOnly \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<YOUR_ARN>"},"Action":"sts:AssumeRole"}]}'

# 3. Attach the two AWS-managed read-only policies
aws iam attach-role-policy --role-name RemediGeniusReadOnly --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-role-policy --role-name RemediGeniusReadOnly --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
```

Prefer the console? IAM → Roles → Create role → AWS account → attach `SecurityAudit` and `ViewOnlyAccess`, and
trust your own identity. The role's ARN looks like `arn:aws:iam::<account>:role/RemediGeniusReadOnly`.

> **Why this matters:** if you skip the role, the workstation copies your profile's own credentials into the desk.
> If that profile is an administrator or a long-term IAM key, you've put powerful credentials in a container. The
> read-only role avoids that. See [how credentials stay safe](#how-your-aws-credentials-stay-safe) below.

### 3. Clone, then set your model key

```sh
git clone https://github.com/RajaRenga/RemediGenius-CE.git
cd RemediGenius-CE

export REMEDIGENIUS_MODEL_KEY="your-model-key"     # PowerShell: $env:REMEDIGENIUS_MODEL_KEY="your-model-key"
```

Set the key in your environment, never on the command line or in chat.

### 4. Run

```sh
python tools/workstation.py run \
  --aws-profile <profile> \
  --read-role-arn arn:aws:iam::<account>:role/RemediGeniusReadOnly \
  --model-base-url https://YOUR_PROVIDER/v1
```

The first start builds the desk image (about a minute), restores any earlier state, and starts both containers.
`run` then keeps the AWS credentials fresh (they expire hourly). Optional: add `--iac ~/src/infra` to mount your
Terraform/CloudFormation/CDK repos read-only so CE can locate fixes.

**You should see:** `RemediGenius-CE is running: http://127.0.0.1:9125/chat?profile=remedigenius`, plus a line
saying when the desk's AWS credentials expire.

### 5. Open the dashboard

```sh
python tools/workstation.py login     # prints the private login — keep it out of chat and screenshots
```

Open `http://127.0.0.1:9125/chat?profile=remedigenius` and sign in. The first scan runs about 3 minutes after
start, then every 6 hours. Type `/triage` to see the board without a model call, or ask "what needs my attention?".

**You should see:** a P1–P4 queue of grouped issues with scoring reasons, and a coverage line. "Not enabled" or
"access denied" on a source is a blind spot, not a clean result. If the board is empty, check the coverage line
before assuming the account is clean.

### How your AWS credentials stay safe

- The workstation uses your profile only to **assume the read-only role** via STS, which returns **temporary
  1-hour credentials**. Your long-term keys never enter a container.
- Those temporary credentials go **only into the desk container**, mounted read-only, file mode 600, non-root.
  The desk runs with a read-only root filesystem, all Linux capabilities dropped, and no privilege escalation.
- The **Hermes/agent container gets no AWS credentials** and can't reach instance metadata. It talks to the desk
  only through a Unix socket that accepts a fixed list of triage commands.
- A botocore **read guard** in the desk refuses any non-read call even if the credentials could write.
- `run` refreshes the credentials every 30 minutes; `refresh` renews them once.

The credentials live in a Docker volume on your machine, protected by file permissions. Anyone with Docker/host
admin access can read them — the same trust boundary as your `~/.aws/credentials`. That's expected for a
workstation; don't run this on a shared or untrusted host.

### Stop and start

```sh
python tools/workstation.py stop      # final checkpoint, then remove the containers (state is kept)
python tools/workstation.py run ...   # start again; state restores from ~/RemediGenius-CE
```

Full reference: [WORKSTATION.md](WORKSTATION.md).

---

## Path 2: Existing Hermes

Already running Hermes **0.23.1**? Add the `remedigenius` profile and reuse your model configuration. On other
Hermes versions, use the Docker workstation above instead — it runs alongside your install without changing it.

```sh
python -m pip install -e .
python tools/install_local_hermes.py --check
python tools/install_local_hermes.py --clone-from <profile> --aws-profile <profile> --region us-east-1
python -m rgtriage --durable doctor
python -m rgtriage --durable scan
hermes -p remedigenius chat
```

Use a read-only AWS profile or role, the same as the workstation. **Note:** this path runs the desk as a subprocess
in your credential environment — it does not isolate credentials from Hermes the way the containers do. If you need
that boundary, use the Docker workstation. Full guide: [LOCAL-HERMES.md](LOCAL-HERMES.md).

---

## Path 3: AWS Spot

An always-on private desk in your account: one Spot instance plus a private S3 bucket. Terraform provisions the
instance, the bucket, and the read-only audit role for you, so there's less manual IAM than the workstation — but
you need Terraform and a provisioning identity.

```sh
python tools/package_release.py --spot dist/remedigenius-ce-spot.zip
cd deploy/aws-single
cp example.tfvars local.tfvars     # set account_id, subnet_id, source_zip, model_*
terraform init
terraform plan -var-file=local.tfvars
terraform apply -var-file=local.tfvars
```

You'll need Terraform ≥ 1.10, AWS CLI v2 with the Session Manager plugin, a subnet with outbound HTTPS, and your
model key in Secrets Manager. The full guide walks each prerequisite: [deploy/aws-single/README.md](../deploy/aws-single/README.md).
Reach the dashboard through an SSM port-forward; the instance has no inbound ports.

---

## One account vs an organization

The quickstart above reads a single account. If you use AWS Organizations and want CE to read member accounts,
that's a separate, reviewed step — one read-only role per member account, deployed once as a StackSet. Ask the
agent "help me onboard the other accounts" or run `rgtriage onboarding`. Don't broaden the runtime's permissions to
do it. See [MULTI-ACCOUNT.md](MULTI-ACCOUNT.md) and [ACCESS-QUICKSTART.md](ACCESS-QUICKSTART.md).

## If the first run fails

- **Desk won't start / `ModuleNotFoundError`** — make sure you're on v0.9.1 or later; older workstation images were
  missing a storage dependency. `docker logs remedigenius-ce-desk` shows the error.
- **Board shows `denied`** — the read role lacks a permission; check the role has `SecurityAudit` + `ViewOnlyAccess`
  and that no SCP blocks it.
- **No model / 401** — the key or `--model-base-url` is wrong. The desk still scans; set the model in the dashboard.
- More: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Before you rely on it

Read [LIMITS.md](LIMITS.md) for what is and isn't covered and what reaches your model provider. Then tell the desk
what matters in the **Knowledge** tab — owners, critical applications, accepted risks — so priorities reflect your
organization, not generic defaults.