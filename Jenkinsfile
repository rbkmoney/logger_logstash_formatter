#!groovy

build('logger_logstash_formatter', 'docker-host') {
  checkoutRepo()
  loadBuildUtils()

  def pipeDefault
  runStage('load pipeline') {
    env.JENKINS_LIB = "build_utils/jenkins_lib"
    pipeDefault = load("${env.JENKINS_LIB}/pipeDefault.groovy")
  }

  pipeDefault() {
    runStage('compile') {
      sh 'make wc_compile'
    }
    runStage('lint') {
      sh 'make wc_lint'
    }
    runStage('dialyzer') {
      sh 'make wc_dialyze'
    }
    runStage('xref') {
      sh 'make wc_xref'
    }
    runStage('test') {
      sh "make wc_test"
    }
  }
}

