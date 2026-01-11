# 🛡️ TechGuardrails - Enterprise Edition

**Transform – Evolve – Operate | Your Co-pilot Enabling Future with Care**

Enterprise AWS Cloud Governance, Compliance, FinOps & Security Platform with AI-Powered Features

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://techguardrails.streamlit.app)

## 🎯 Platform Highlights

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | **27,146** |
| **Main Application** | 5,233 lines |
| **Enterprise Modules** | 21,913 lines |
| **Navigation Pages** | 21 |
| **Database Models** | 19 |
| **AI Tools** | 8 agentic tools |
| **Account Templates** | 15+ |
| **Remediation Services** | 10 AWS services |

---

## 📦 Enterprise Modules

| Module | Lines | Features |
|--------|-------|----------|
| **account_lifecycle_enhanced** | 5,292 | 15+ templates, RBAC, approval workflows |
| **eks_vulnerability_enterprise** | 5,160 | Trivy, Snyk, Inspector, ML scoring |
| **policy_as_code_platform** | 1,943 | Full policy lifecycle |
| **scp_policy_engine** | 1,628 | SCP management & simulation |
| **batch_remediation_production** | 1,612 | 10-service remediation |
| **windows_server_remediation** | 1,306 | Windows patching scripts |
| **linux_distribution_remediation** | 1,234 | Linux patching scripts |
| **crewai_finops_agents** | 980 | Multi-agent AI system |
| **multi_account_policy_manager** | 920 | Organizations, StackSets |
| **claude_predictions** | 916 | AI forecasting |
| **unified_remediation_dashboard** | 889 | Cross-service remediation |

---

## ✨ Features Overview

### 🎮 Demo/Live Mode Toggle
**Seamlessly switch between sample data and real AWS data:**
- **🟠 Demo Mode** - Realistic sample data for demonstrations
- **🟢 Live Mode** - Real-time data from AWS
- Toggle in sidebar - instant switch
- All pages respect the current mode

---

### 🔨 Build & Run Phase (Foundation)
| Feature | Description |
|---------|-------------|
| Operations Dashboard | Real-time health metrics, component status |
| Findings Analysis | Filter, sort, bulk actions on security findings |
| Batch Remediation | Execute fixes across multiple resources |
| OS-Specific Remediation | Windows Server & Linux scripts by version |
| Incident Response | Create, track, and resolve security incidents |

### 🔄 Evolve & Improve Phase (Enhancement)
- Maturity Assessment with gap analysis
- Remediation Intelligence & Automation
- AI Policy Generator (SCP, IAM, Config Rules)

### 🚀 Transform Phase (Innovation)
- Zero-Trust Architecture Planning
- AIOps Platform - Self-healing compliance
- Human-AI Collaboration scenarios
- FinOps-Security-Compliance Convergence

---

## 🆕 NEW Feature Pages

### 💰 FinOps Center
**Complete Cloud Financial Operations:**

| Tab | Features |
|-----|----------|
| **📊 Cost Overview** | MTD spend, forecasts, service breakdown, account costs |
| **💡 Savings** | RI/SP recommendations, right-sizing, idle resources |
| **📋 Budgets** | Budget tracking, utilization, alerts |
| **🔍 Anomalies** | Cost spike detection, root cause analysis |
| **🤖 AI Advisor** | Claude-powered cost optimization |

### 🐳 Container Security Center
**EKS Vulnerability Management:**

| Tab | Features |
|-----|----------|
| **📊 Dashboard** | Cluster overview, vulnerability distribution |
| **🔍 Scanner** | Trivy, Snyk, AWS Inspector v2 integration |
| **🎯 Triage** | AI-powered prioritization, ML risk scoring |
| **🔧 Remediation** | Auto-remediation, rollback management |
| **📋 Compliance** | PCI-DSS, HIPAA, SOC 2, ISO 27001 mapping |

### 📦 Account Lifecycle Management
**Complete Account Governance:**

| Tab | Features |
|-----|----------|
| **🏪 Marketplace** | 6+ pre-built account templates |
| **🆕 Provision** | Readiness validation, cost forecasting |
| **✏️ Modify** | Add/remove guardrails, change OU |
| **📤 Offboard** | Data retention, approval workflow |
| **📊 Portfolio** | Account distribution, status tracking |

### 📜 Policy as Code Platform
**Unified Policy Management:**

| Tab | Features |
|-----|----------|
| **📚 Catalog** | SCP, OPA, Config, KICS policies |
| **✍️ Author** | Policy editor with AI enhancement |
| **🧪 Test** | Syntax validation, dry-run testing |
| **🚀 Deploy** | Multi-account deployment, rollout strategies |
| **📊 Monitor** | Violation tracking, effectiveness metrics |

### 🏢 Multi-Account Policy Manager
**AWS Organizations Integration:**

| Tab | Features |
|-----|----------|
| **🏗️ Organization** | OU structure visualization |
| **📦 StackSets** | CloudFormation deployment |
| **📊 Aggregator** | Config compliance aggregation |
| **📜 History** | Deployment audit trail |

### 🧠 AI Predictions Engine
**Proactive Insights:**

| Tab | Features |
|-----|----------|
| **💰 Cost** | 30/60/90 day forecasts |
| **🛡️ Security** | Risk predictions, threat assessment |
| **📋 Compliance** | Drift prediction, control risks |
| **📈 Capacity** | Resource utilization forecasting |
| **🚨 Alerts** | Proactive alert generation |

---

### 🤖 AI-Powered Features

#### AI Policy Advisor
- Policy Creation with compliance mapping
- Policy Analysis & optimization
- Quick Optimization suggestions
- Knowledge Base Q&A

#### 🦾 Agentic AI Security Agent
**Autonomous security investigation with 8 tools:**
- `get_security_findings` - Query security findings
- `get_account_info` - AWS account information
- `analyze_resource` - Deep-dive analysis
- `generate_remediation_script` - Boto3 scripts
- `create_policy` - Generate SCPs/IAM policies
- `execute_remediation` - Run with dry-run
- `get_compliance_summary` - Compliance trends
- `search_policies` - Policy store search

---

### ⚙️ Operational Controls
**User-configurable parameters:**
- Health Thresholds (excellent/good/fair/poor)
- SLA Management by severity
- Alert Rules with cooldowns
- MTTR Targets
- Severity Weights
- **MTTR Targets** - Set Mean Time To Remediate goals
- **Severity Weights** - Control how findings impact health scores
- **Coverage Targets** - Define target coverage percentages

**Dynamic Health Score Calculation:**
```
Overall Health = (
  Compliance Score × 30% +
  Finding Impact × 25% +
  SLA Compliance × 20% +
  Remediation Rate × 10% +
  Policy Coverage × 10% +
  Account Coverage × 5%
)
```

### 📈 New Database Models
- `OperationalConfig` - Store user configurations
- `SLADefinition` - Define SLAs by type and severity
- `OperationalMetric` - Historical metrics for trends
- `AlertRule` - User-defined alerting rules
- `AlertHistory` - Track triggered alerts
- `MaturityAssessment` - Track capability maturity
- `RemediationPlaybook` - Store remediation scripts

## 🚀 Deploy to Streamlit Cloud

### Quick Start (5 Minutes)

1. **Fork/Clone Repository**
```bash
git clone https://github.com/your-username/techguardrails.git
cd techguardrails
```

2. **Push to GitHub**
```bash
git init
git add .
git commit -m "Initial TechGuardrails deployment"
git remote add origin https://github.com/your-username/techguardrails.git
git push -u origin main
```

3. **Deploy on Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Click **"New app"**
   - Select your repository → `streamlit_app.py`
   - Click **"Deploy"**

4. **Configure Secrets (for AI features)**
   - Click **"Manage app"** → **Settings** → **Secrets**
   - Add your Anthropic API key:
   ```toml
   [anthropic]
   api_key = "YOUR_ANTHROPIC_API_KEY"
   ```
   - Click **"Save"**
   - Get your API key at: https://console.anthropic.com/

## 🎮 Demo Mode

The app runs in **Demo Mode** by default:
- ✅ 50 sample AWS accounts
- ✅ 100 security findings
- ✅ Sample policies and exceptions
- ✅ Historical compliance scores
- ✅ No AWS credentials required!

To use with real AWS:
```toml
[app]
enable_demo_mode = false

[aws]
access_key_id = "YOUR_KEY"
secret_access_key = "YOUR_SECRET"
```

## 📁 Project Structure

```
techguardrails/
├── .streamlit/
│   ├── config.toml           # Theme and configuration
│   └── secrets.toml.example  # Secrets template
├── modules/                   # Enterprise modules (21,913 lines)
│   ├── __init__.py
│   ├── account_lifecycle_enhanced.py      # Account templates, RBAC
│   ├── eks_vulnerability_enterprise_complete.py  # Container scanning
│   ├── batch_remediation_production.py    # Multi-service remediation
│   ├── claude_predictions.py              # AI forecasting
│   ├── policy_as_code_platform.py         # Policy lifecycle
│   ├── multi_account_policy_manager.py    # Organizations
│   ├── scp_policy_engine.py               # SCP management
│   ├── crewai_finops_agents.py            # Multi-agent AI
│   ├── unified_remediation_dashboard.py   # Cross-service remediation
│   ├── windows_server_remediation_MERGED_ENHANCED.py
│   └── linux_distribution_remediation_MERGED_ENHANCED.py
├── streamlit_app.py          # Main application (5,233 lines)
├── requirements.txt          # Dependencies
├── .gitignore               # Git ignore rules
└── README.md                # This file
```

## 🔑 API Keys & Permissions

### For AI Features (Anthropic Claude)
Get your API key at: https://console.anthropic.com/

```toml
[anthropic]
api_key = "sk-ant-..."
```

### For AWS Sync (Optional)
Only needed if you want to sync with AWS Organizations/Security Hub:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "organizations:ListAccounts",
      "securityhub:GetFindings",
      "config:DescribeComplianceByConfigRule"
    ],
    "Resource": "*"
  }]
}
```

## 🗄️ Database Options

### SQLite (Default - Demo)
- Data resets on each deployment
- Good for demos and testing

### PostgreSQL (Production)

**Supabase (Free tier):**
```toml
[database]
type = "postgresql"
url = "postgresql://postgres.[ref]:[pass]@aws-0-[region].pooler.supabase.com:6543/postgres"
```

**Neon (Free tier):**
```toml
[database]
type = "postgresql"
url = "postgresql://[user]:[pass]@[endpoint].neon.tech/[db]?sslmode=require"
```

## 📱 Pages & Navigation (21 Pages)

| Page | Description |
|------|-------------|
| 🏠 Dashboard | Executive overview with dynamic health metrics |
| 🔨 Build & Run | Operations, findings, batch remediation, incident response |
| 🔄 Evolve & Improve | Maturity assessment, automation, AI policy generator |
| 🚀 Transform | Zero-trust, AIOps, human-AI collaboration |
| 💰 FinOps Center | Cost visibility, savings, budgets, anomalies, AI advisor |
| 🐳 Container Security | **NEW** - EKS vulnerabilities, Trivy/Snyk/Inspector |
| 📦 Account Lifecycle | **NEW** - Templates, provisioning, offboarding |
| 📜 Policy as Code | **NEW** - Author, test, deploy, monitor policies |
| 🏢 Multi-Account Manager | **NEW** - Organizations, StackSets, aggregator |
| 🧠 AI Predictions | **NEW** - Cost, security, compliance, capacity forecasts |
| 🤖 AI Policy Advisor | Policy creation, analysis, optimization |
| 🦾 AI Security Agent | **Autonomous agentic AI** with 8 tools |
| ⚙️ Operational Controls | Thresholds, SLAs, alerts, weights |
| 🏢 Accounts | Account management |
| 🔍 Findings | Security findings with filters |
| 📜 Policies | Policy store with approval workflow |
| 🔧 Remediation | Remediation history |
| ⚠️ Exceptions | Exception management |
| 📝 Audit Logs | Complete audit trail |
| 📊 Analytics | Reports and AI summaries |
| 🔄 Sync | AWS data synchronization |
| 🛠️ Settings | Configuration and status |

## 🛠️ Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create local secrets
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit secrets.toml with your settings

# Run locally
streamlit run streamlit_app.py
```

## 🔧 Troubleshooting

### "Claude API not available"
- Ensure you've added your Anthropic API key to Streamlit Secrets
- Get your API key at: https://console.anthropic.com/
- Demo mode still works without Claude API (no AI features)

### "AWS not connected"
- Add AWS credentials to Streamlit Secrets (optional)
- Or use demo mode (no AWS required for core features)

### "Database error"
- SQLite resets on deployment
- Use PostgreSQL for persistence

## 📈 Roadmap

- [x] Agentic AI Security Agent with tool use
- [ ] Multi-turn agent conversations with memory
- [ ] Agent approval workflows for production changes
- [ ] Integration with AWS Step Functions for long-running remediation
- [ ] Custom tool creation UI
- [ ] Multi-region AWS support
- [ ] Real-time compliance monitoring
- [ ] Slack/Teams notifications
- [ ] PDF report generation
- [ ] Custom policy templates
- [ ] SSO integration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License

---

**TechGuardrails** - Transform – Evolve – Operate 🛡️

*Powered by Anthropic Claude API*
