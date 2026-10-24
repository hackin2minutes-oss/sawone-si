# AI infrastructure (deliberately vulnerable: see README.md)

resource "azurerm_cognitive_account" "openai" {
  name                          = "acme-openai"
  location                      = "swedencentral"
  resource_group_name           = "rg-ai"
  kind                          = "OpenAI"
  sku_name                      = "S0"
  public_network_access_enabled = true    # planted: reachable from the internet, no network rules
  local_auth_enabled            = true    # planted: API keys instead of Entra ID
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "gpt-4o"
  cognitive_account_id = azurerm_cognitive_account.openai.id
  model {
    format  = "OpenAI"
    name    = "gpt-4o"
    version = "2024-08-06"
  }
  sku {
    name = "Standard"
  }
  # planted: no rai_policy_name, so no custom content filter
}

resource "azurerm_machine_learning_workspace" "ml" {
  name                          = "acme-ml"
  location                      = "swedencentral"
  resource_group_name           = "rg-ai"
  application_insights_id       = "x"
  key_vault_id                  = "x"
  storage_account_id            = "x"
  public_network_access_enabled = true    # planted
  identity {
    type = "SystemAssigned"
  }
}

resource "aws_bedrockagent_agent" "support" {
  agent_name              = "support"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-5-sonnet-20240620-v1:0"
  instruction             = "You are the support agent for Acme Retail. Help customers with orders and refunds."
  # planted: no guardrail_configuration
}

resource "aws_sagemaker_notebook_instance" "lab" {
  name                   = "acme-lab"
  role_arn               = "arn:aws:iam::123456789012:role/sagemaker"
  instance_type          = "ml.t3.medium"
  direct_internet_access = "Enabled"     # planted
  root_access            = "Enabled"     # planted
  # planted: no kms_key_id
}

resource "aws_sagemaker_endpoint_configuration" "churn" {
  name = "churn"
  production_variants {
    variant_name           = "main"
    model_name             = "churn-model"
    initial_instance_count = 1
    instance_type          = "ml.m5.large"
  }
  # planted: no kms_key_arn
}

resource "google_vertex_ai_endpoint" "rank" {
  name         = "rank"
  display_name = "rank"
  location     = "me-central2"
  # planted: no encryption_spec (customer-managed key)
}
