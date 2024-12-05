pipeline {
    agent any
    stages {
        stage('Install Dependencies') {
            steps {
                sh '''
                    #!/bin/bash
                    set -e

                    python3 -m venv venv
                    source venv/bin/activate

                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }
        stage('Run Script') {
            steps {
                withCredentials([
                    file(credentialsId: 'OPENSTACK_CREDENTIALS', variable: 'OPENRC_FILE'),
                    string(credentialsId: 'VAULT_PASSWORD', variable: 'VAULT_PASSWORD')
                ]) {
                    sh '''
                        #!/bin/bash
                        set -e

                        source venv/bin/activate
                        eval $(oidc-agent-service use)
                        source $OPENRC_FILE
                        export VAULT_PASSWORD=${VAULT_PASSWORD}
                        python ensure_enough.py
                        deactivate
                    '''
                }
            }
        }
    }
}
