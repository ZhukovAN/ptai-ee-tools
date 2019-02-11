Pipeline usage:

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