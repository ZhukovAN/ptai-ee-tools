cd rest-api
call mvn clean install -DskipTests=true
cd ../ptai-data-structures
call mvn clean install -DskipTests=true
cd ../jce-restrictions-checker
call mvn clean install -DskipTests=true
cd ../generic-client-lib
call mvn clean install -DskipTests=true
cd ../ptai-jenkins-plugin
call mvn clean install -DskipTests=true
cd ../ptai-cli-plugin
call mvn clean install -DskipTests=true
cd ../ptai-integration-service
call mvn clean install -DskipTests=true
