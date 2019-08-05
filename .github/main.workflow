workflow "Nightly CI" {
  on = "schedule(0 0 * * *)"
  resolves = ["Trigger Instructure.Paseto pipeline"]
}

action "Trigger Instructure.Paseto pipeline" {
  uses = "Azure/github-actions/pipelines@master"
  secrets = ["AZURE_DEVOPS_TOKEN"]
  env = {
    AZURE_DEVOPS_URL = "https://dev.azure.com/instructure-github"
    AZURE_PIPELINE_NAME = "instructure.paseto"
    AZURE_DEVOPS_PROJECT = "paseto"
  }
}
