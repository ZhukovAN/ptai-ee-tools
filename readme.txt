svc_ptai / P@ssw0rd / 58cc5c468a2a13865f46feb05232d343

Pipeline usage:

node('master') {
   def mvnHome
   stage('Preparation') { // for display purposes
      git 'https://github.com/ptssdl/App01.git'
      mvnHome = tool 'MAVEN 3.5.3'
   }
   stage('Build') {
      // Run the maven build
      if (isUnix()) {
         sh "'${mvnHome}/bin/mvn' -Dmaven.test.failure.ignore clean package"
      } else {
         bat(/"${mvnHome}\bin\mvn" -Dmaven.test.failure.ignore clean package/)
      }
   }
   stage('SAST') {
      ptaiUiSast sastConfigName: 'Local Jenkins (password authentication) and ai-post-2012.ptsecurity.ru',
        uiProject: 'App01.20190204',
        failIfSastFailed: true,
        failIfSastUnstable: false,
        sastAgentNodeName: 'LOCAL',
        verbose: true,
        transfers: [
            [includes: '**/*', excludes: 'target/**', flatten: false,
             useDefaultExcludes: false, patternSeparator: '[, ]+',
             removePrefix: '']
        ]
   }
   stage('Results') {
      archiveArtifacts 'target/*.war, sast.report.json, sast.report.html'
      cleanWs();
   }
}