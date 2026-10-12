terraform {
  required_version = "= 1.14.7"
  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "= 1.293.0"
    }
  }
  backend "oss" {}
}

provider "alicloud" {
  region = var.region
  features {
    ecs_instance { replace_on_image_update = true }
  }
}

# Fails planning before paid resources can be proposed for a different account.
data "alicloud_caller_identity" "deployment" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.cloud_account_id
      error_message = "Provider credentials belong to a different cloud account than the explicitly approved deployment."
    }
  }
}
