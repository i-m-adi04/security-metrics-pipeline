Question 3 — Enforce Managed Identity on Azure App Services
What We Are Trying to Achieve
Every application running in Azure needs a secure way to connect to other services — databases, storage, secret vaults. The traditional approach is to embed a username and password directly into the application's configuration. This creates serious security risk: those credentials can be accidentally committed to source code, leaked through application logs, or accessed by anyone who has read access to the server.
Azure provides a better mechanism called a Managed Identity — essentially a secure digital ID card that Azure automatically issues to an application. The application presents this ID card to access other services without ever needing a hardcoded password. If the application is deleted or compromised, the ID card becomes useless. There are no credentials to steal.
The problem is that developers — especially under deadline pressure — often skip this step. They default to the familiar approach of hardcoded credentials because it works and it is faster. Over time, an organisation accumulates dozens of applications running without managed identities, each one a potential security gap.
Our goal: make the secure approach automatic. No developer action required. No exceptions.

What This Solution Does
We wrote a single Azure Policy that acts as an automatic security enforcer across the entire Azure subscription.
Every 15 minutes, the policy scans every App Service in the subscription and asks one question: does this application have a managed identity?

If yes → leave it alone
If no → automatically fix it

The fix happens silently in the background. The developer does not need to do anything. The application gets a managed identity created and attached, and a tag is added to the application so the security team can see it was auto-remediated.

Why We Chose This Approach
We evaluated four different approaches before settling on this one:
Option 1 — Manual review process
A security engineer periodically audits applications and flags those without managed identities. This does not scale. With dozens of teams deploying daily, manual review creates a backlog and human error is inevitable.
Option 2 — Audit-only policy
A policy that reports non-compliant applications on a dashboard but takes no action. This creates noise without resolution. In practice, compliance dashboards showing "40 non-compliant resources" get ignored because fixing them requires manual effort from busy development teams.
Option 3 — Block deployments without managed identity
A policy that prevents any application from deploying if it is missing a managed identity. This is too aggressive — it breaks developer workflows immediately, including emergency hotfixes, and causes significant friction with development teams. It also does not fix the hundreds of existing applications already running without identities.
Option 4 — Automatic remediation (our choice)
A policy that detects the problem and fixes it automatically using Azure's DeployIfNotExists mechanism. Developers are not blocked. Existing non-compliant applications are fixed. New non-compliant deployments are fixed within 15 minutes. The security team gets an audit trail of everything that was auto-remediated.
This approach achieves the security outcome without creating operational friction.

Problems We Encountered and How We Solved Them
Problem 1 — String matching was more fragile than expected
When checking whether an App Service has the right type of identity, the obvious approach was to check if the identity type exactly matches an approved value. However, Azure can return the same identity configuration as different string values depending on the order — for example "SystemAssigned, UserAssigned" and "UserAssigned, SystemAssigned" mean the same thing but are different strings.
Solution: Instead of exact matching, we check whether the string contains the word "UserAssigned" anywhere. This is resilient to any future changes in how Azure formats this value and removes a whole class of potential false positives.
Problem 2 — Some teams have legitimate reasons to not use UserAssigned identities
Certain application architectures are specifically designed around System-Assigned identities — a different type that is tied directly to a single application. Our policy would have forced UserAssigned identities on top of these, creating unnecessary resources and confusing those teams.
Solution: We added an exemption mechanism. A team lead can add a specific tag to their application (policy-exempt: managed-identity-required) and the policy will skip it. This requires a deliberate action — the exemption does not happen by accident — and creates a documented record of approved exceptions.
Problem 3 — Orphaned resources after application deletion
When our policy creates a managed identity for an application, that identity is a separate resource. If the application is later deleted or decommissioned, the identity remains in the resource group with no owner — wasting resources and creating potential security clutter.
Solution: We added a tag to every auto-created identity (owner-app-service: {name}) that records which application it was created for. A weekly cleanup process can use this tag to identify identities whose parent application no longer exists and flag them for human review before deletion. We chose human review over automatic deletion because automatically deleting a live identity that is still in use — perhaps attached to a replacement application — would cause an outage.
Problem 4 — There is a 15-minute window where a new application exists without an identity
The DeployIfNotExists policy evaluates resources approximately every 15 minutes. A new application deployed without an identity will be unprotected during that window.
Solution: For environments requiring zero tolerance, this policy can be paired with a Deny policy that blocks new deployments without an identity altogether. The DeployIfNotExists policy then handles all existing non-compliant resources. Together they eliminate the gap.

How to Deploy This Policy
bash# 1. Create the policy definition at subscription level
az policy definition create \
  --name "deploy-uami-appservice-missing-identity" \
  --display-name "Deploy managed identity to App Services missing UserAssigned identity" \
  --rules azure_policy_q3.json \
  --mode Indexed

# 2. Assign the policy to the subscription
az policy assignment create \
  --name "enforce-appservice-managed-identity" \
  --policy "deploy-uami-appservice-missing-identity" \
  --scope "/subscriptions/{SUBSCRIPTION_ID}" \
  --mi-system-assigned \
  --location eastus

# 3. Trigger remediation for existing non-compliant resources
az policy remediation create \
  --name "remediate-existing-appservices" \
  --policy-assignment "enforce-appservice-managed-identity" \
  --resource-discovery-mode ExistingNonCompliant

Files in This Folder
FileDescription azure_policy_q3.jsonThe complete Azure Policy definition architecture_q3 diagram — open in any browser README.mdThis document

What Happens After Deployment — End to End Story
Monday 9AM: A developer deploys a new payment service application. Under time pressure, they forget to add a managed identity in their Bicep file. The deployment succeeds — Azure does not block it.
Monday 9:15AM: The policy evaluates the new application. It has no managed identity. The existenceCondition check confirms this has not been fixed yet. The policy triggers the ARM template.
Monday 9:16AM: A managed identity named uami-payment-service-auto is created in the same resource group and region as the application. It is attached to the application. The application is tagged with security-remediation: auto-managed-identity.
Monday 10AM: The security engineer sees the tag in the compliance dashboard. They raise a ticket to the development team: "Your payment service was auto-remediated — please update your Bicep file to include the identity block so future deployments do not require auto-remediation."
Tuesday: The developer updates the Bicep file. Future deployments of the payment service include the identity from the start. The policy evaluates and finds it compliant — no action taken.
The outcome: The security gap was closed automatically within 15 minutes. The developer was not blocked or interrupted. The security team has a complete audit trail. The root cause was addressed through the ticket process rather than an emergency.
