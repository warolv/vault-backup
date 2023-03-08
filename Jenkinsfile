// Create Jenkins scheduled job for daily vault backup example
// I am using Vault Plugin in Jenkins https://plugins.jenkins.io/hashicorp-vault-plugin
// to add secrets as env variables during job execution.
// Read more about how to integrate this plugin into jenkins here: https://igorzhivilo.com/jenkins/how-to-read-vault-secrets-from-declarative-pipeline

// During job execution POD will be created with 2 contaienrs: awscli to use aws s3 utility, and push created encrypted dump to private s3 bucket (vault-backups), python to run VaultHandler.*


def configuration = [vaultUrl: "${VAULT_URL}",  vaultCredentialId: "vault-role-app", engineVersion: 2]

def secrets = [
  [path: 'secret/jenkins/aws', engineVersion: 2, secretValues: [
    [envVar: 'GCP_SERVICE_ACCOUNT', vaultKey: 'google_service_account'],
    [envVar: 'GCP_PROJECT_ID', vaultKey: 'id_Project']
    [envVar: 'GCP_LOCATION', vaultKey: 'name_region ' ]
    [envVar: 'GCP_SECRET_ACCESS_KEY', vaultKey: 'gcp_secret_key']]],
  [path: 'secret/jenkins/vault-backup', engineVersion: 2, secretValues: [
    [envVar: 'VAULT_ADDR', vaultKey: 'vault_url'],
    [envVar: 'ROLE_ID', vaultKey: 'role_id'],
    [envVar: 'SECRET_ID', vaultKey: 'secret_id'],
    [envVar: 'VAULT_PREFIX', vaultKey: 'vault_prefix'],
    [envVar: 'ENCRYPTION_KEY', vaultKey: 'encryption_key']]],
]

def podTemplate = """
                apiVersion: v1
                kind: Pod
                spec:
                  containers:
                    - name: gcloud-sdk
                      image: gcr.io/google.com/cloudsdktool/cloud-sdk:latest
                      command:
                      - cat
                      tty: true
                    - name: python
                      image: python:3.6
                      command:
                      - cat
                      tty: true
                """.stripIndent().trim()

pipeline {
  agent {
    any {
      defaultContainer 'jnlp'
      yaml "${podTemplate}"
    }
  }

  environment {
    GCP_LOCATION = "name_region"
  }

  stages {
    stage('Backup Jenkins'){
      steps {
        container('python'){
          dir("${env.WORKSPACE}/pipelines-k8s/vault-backup/") {
            withVault([configuration: configuration, vaultSecrets: secrets]){
              sh """#!/bin/bash
                pip install -r requirements.txt
                python vault_handler.py dump
                tar -zcvf vault_secrets.json.enc.tar.gz vault_secrets.json.enc
              """
            }
          }
        }
        container('gcloud_CLI'){
          dir("${env.WORKSPACE}/pipelines-k8s/vault-backup/") {
            withVault([configuration: configuration, vaultSecrets: secrets]){
              sh '''
                 cp vault_secrets.json.enc.tar.gz gs://gcs-asia-northeast1-devops/$(date +%Y%m%d%H%M)/vault_secrets.json.enc.tar.gz
              '''
            }
          }
        }
      }
    }
  }
}
