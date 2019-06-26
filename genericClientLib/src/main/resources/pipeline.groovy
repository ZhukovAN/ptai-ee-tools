def aicPath = 'C:\\Program Files (x86)\\Positive Technologies\\Application Inspector Agent\\aic.exe'
  
node("${PTAI_NODE_NAME}") {
    def retStatus = 0;
  
    stage('SAST') {
        if (isUnix()) {
            currentBuild.result = "UNSTABLE";
            println 'PT AI must be deployed on a Windows host';
            return;
        }
        cleanWs();
		
        batchScript = "\"${aicPath}\" ";
        if ("${PTAI_SETTINGS_JSON}"?.trim()) {
            new File("${WORKSPACE}\\settings.aiproj").write("${PTAI_SETTINGS_JSON}");
            batchScript += "--project-settings-file \"${WORKSPACE}\\settings.aiproj\" ";
            if ("${PTAI_SETTINGS_JSON}"?.trim()) {
            }
        } else {
            batchScript += "--project-name \"${PTAI_PROJECT_NAME}\" ";
        }

        batchScript += "--scan-target \"${WORKSPACE}\\SCAN\" "
        batchScript += "--reports \"HTML|JSON\" "
        batchScript += "--reports-folder \"${WORKSPACE}\\REPORTS\" "
        batchScript += "--restore-sources "
        batchScript += "--sync "
          
        retStatus = bat(script: batchScript, returnStatus: true);
        println "AI return status ${retStatus}";
        if ((0 == retStatus) || (10 == retStatus) || (6 == retStatus)) 
            archiveArtifacts 'REPORTS/*';

        if (0 == retStatus) {
            currentBuild.result = "SUCCESS";
            println 'SAST policy assessment OK';
        } else if (10 == retStatus) {
            currentBuild.result = "FAILURE";
            println 'SAST policy assessment failed';
        } else if (-1 == retStatus) {
            currentBuild.result = "UNSTABLE";
            println 'Another AI instance started already';
        } else if (2 == retStatus) {
            currentBuild.result = "UNSTABLE";
            println 'Scan folder not found';
        } else if (3 == retStatus) {
            currentBuild.result = "UNSTABLE";
            println 'AI license problem';
        } else if (4 == retStatus) {
            currentBuild.result = "UNSTABLE";
            println 'Project not found';
        } else if (5 == retStatus) {
            currentBuild.result = "UNSTABLE";
            println 'Project settings error';
        } else if (6 == retStatus) {
            currentBuild.result = "UNSTABLE";
            println 'Minor errors during scan';
        } else {
            currentBuild.result = "FAILURE";
            println 'Unknown problem';
        }
        cleanWs();
    }
}
