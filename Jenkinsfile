// Pipeline CI/CD - SecureDev Tickets (EP3 OCY1102)
// Etapas: Checkout -> Entorno -> SAST/SCA -> Pruebas -> Build -> Escaneo imagen -> Deploy -> ZAP -> Reportes
pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    timeout(time: 40, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }

  triggers { pollSCM('H/5 * * * *') }   // revisa cambios en GitHub cada ~5 min (en localhost no hay webhook)

  environment {
    // Secretos guardados en Jenkins (Manage Jenkins > Credentials), nunca en el repositorio
    SECRET_KEY             = credentials('securedev-secret-key')
    GRAFANA_ADMIN_PASSWORD = credentials('grafana-admin-password')
    COMPOSE_PROJECT_NAME   = 'securedev'
  }

  stages {

    stage('1. Checkout y trazabilidad') {
      steps {
        checkout scm
        sh '''
          mkdir -p reports
          {
            echo "build=$BUILD_NUMBER"
            echo "job=$JOB_NAME"
            echo "fecha_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "commit=$(git rev-parse HEAD)"
            git log -1 --pretty="autor=%an <%ae>"
            git log -1 --pretty="mensaje=%s"
            docker --version
            docker compose version
          } | tee reports/build-info.txt
        '''
      }
    }

    stage('2. Preparar entorno Python') {
      steps {
        sh '''
          python3 -m venv .venv
          . .venv/bin/activate
          pip install --quiet --upgrade pip
          pip install --quiet -r requirements.txt -r requirements-dev.txt
          pip freeze > reports/pip-freeze.txt
        '''
      }
    }

    stage('3. Análisis de seguridad (SAST + SCA)') {
      parallel {
        stage('SAST - Bandit (código)') {
          steps {
            sh '''
              . .venv/bin/activate
              bandit -r app.py -f txt -o reports/bandit.txt || true
              cat reports/bandit.txt
              bandit -r app.py -ll        # falla si hay hallazgos de severidad MEDIA o superior
            '''
          }
        }
        stage('SCA - pip-audit (dependencias)') {
          steps {
            sh '''
              . .venv/bin/activate
              rc=0
              pip-audit -r requirements.txt --desc > reports/pip-audit.txt 2>&1 || rc=$?
              cat reports/pip-audit.txt
              exit $rc                    # falla si alguna dependencia tiene CVE conocido
            '''
          }
        }
      }
    }

    stage('4. Pruebas automatizadas') {
      steps {
        sh '''
          . .venv/bin/activate
          pytest -v --junitxml=reports/junit.xml
        '''
      }
      post { always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' } }
    }

    stage('5. Construir imagen Docker') {
      steps {
        sh '''
          docker compose build app
          docker tag securedev-app:latest securedev-app:$BUILD_NUMBER
        '''
      }
    }

    stage('6. Escaneo de la imagen (Trivy)') {
      steps {
        // Solo informa (exit-code 0): las vulnerabilidades de la imagen base se documentan en el informe
        sh '''
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ \
            aquasec/trivy:latest image --severity HIGH,CRITICAL --ignore-unfixed --no-progress \
            securedev-app:$BUILD_NUMBER | tee reports/trivy-image.txt
        '''
      }
    }

    stage('7. Despliegue (app + Prometheus + Grafana)') {
      steps {
        sh '''
          docker compose up -d --build
          for i in $(seq 1 30); do
            status=$(docker inspect --format '{{.State.Health.Status}}' $(docker compose ps -q app) 2>/dev/null || echo starting)
            echo "estado de salud de app: $status"
            if [ "$status" = "healthy" ]; then exit 0; fi
            sleep 3
          done
          docker compose logs --tail=50 app
          exit 1
        '''
      }
    }

    stage('8. Pruebas dinámicas - OWASP ZAP') {
      steps {
        sh '''
          docker rm -f zap-scan >/dev/null 2>&1 || true
          docker run --name zap-scan --user root --network securedev-net ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py -t http://app:8000 -m 2 -r zap-report.html -J zap-report.json -I || true
          docker cp zap-scan:/zap/wrk/zap-report.html reports/zap-report.html
          docker cp zap-scan:/zap/wrk/zap-report.json reports/zap-report.json
          docker rm zap-scan
          python3 ci/check_zap.py reports/zap-report.json
        '''
      }
    }
  }

  post {
    always {
      sh 'docker compose ps || true'
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
    }
    success { echo 'Pipeline OK: construido, probado, desplegado y escaneado.' }
    failure {
      sh 'docker compose logs --tail=40 app || true'
      echo 'Pipeline FALLÓ: revisa la etapa en rojo y los reportes archivados.'
    }
  }
}
