pipeline {
  agent any
  stages {
    stage('Checkout Scm') {
      steps {
        git 'https://github.com/usegalaxy-it/vgcn-infrastructure.git'
      }
    }

        stage('Shell script 0') {
                steps {
                        withCredentials([file(credentialsId: 'openstack_rc_file_covalaxy', variable: 'OPENSTACK_CREDENTIALS')]) {
                        
                        sh"""#!/bin/bash
                        python --version
                        python3 --version
                                python -m venv openstack_cli1
                                . openstack_cli1/bin/activate
                                        set +x
                                        .  \$OPENSTACK_CREDENTIALS
                                        [ -f ansible.cfg ] && rm ansible.cfg
                                        python -m pip install --upgrade pip
                                        pip install -q -r requirements.txt
                                        pip install --upgrade setuptools

                                                TBD=`openstack server list --name vgcnbwc-worker --status SHUTOFF --format csv |cut -f1 -d,| tr -d '"'|paste -s -d' '| sed -e 's|ID||g'`

                                                if [ -z \$TBD ];then
                                                        echo "***"
                                                                echo "No worker nodes in shutoff status to delete"
                                                                echo "***"
                                                else
                                                        echo "Deleting \$TBD"
                                                                openstack server delete \$TBD
                                                                fi
                                                                deactivate
                                                               
                            """
                        }

                }
        }

        stage('Shell script 1') {
                steps {
                        withCredentials([file(credentialsId: 'openstack_rc_file_covalaxy', variable: 'OPENSTACK_CREDENTIALS')]) {
                        
                        sh"""#!/bin/bash
                                
                                        . openstack_cli1/bin/activate
                                        set +x
                                        .  \$OPENSTACK_CREDENTIALS

                                        [ -f ansible.cfg ] && rm ansible.cfg
                                     

                                                TBD=`openstack server list --name vgcnbwc-worker --status ERROR --format csv |cut -f1 -d,| tr -d '"'|paste -s -d' '| sed -e 's|ID||g'`

                                                if [ -z \$TBD ];then
                                                        echo "***"
                                                                echo "No worker nodes in error status to delete"
                                                                echo "***"
                                                else
                                                        echo "Deleting \$TBD"
                                                                openstack server delete \$TBD
                                                                fi
                                                                deactivate
                                                                
                            """
                        }

                }
        }

        stage('Shell script 2') {
                steps {
                        withCredentials([file(credentialsId: 'openstack_rc_file_covalaxy', variable: 'OPENSTACK_CREDENTIALS'),file(credentialsId: 'ansible_vault', variable: 'VAULT_PASS')]) {
                                
                                sh"""#!/bin/bash
                               
                                        . openstack_cli1/bin/activate

                                        set +x
                                        .  \$OPENSTACK_CREDENTIALS

                                        [ -f ansible.cfg ] && rm ansible.cfg
                                       
                                                set -x
                                                pykwalify -d resources.yaml -s schema.yaml
                                                ansible-vault decrypt userdata.yaml --vault-password-file \$VAULT_PASS
                                                python ensure_enough.py


                                                deactivate
                                                rm -rf openstack_cli1
                                """
                        }

                }
        

}
}
}
