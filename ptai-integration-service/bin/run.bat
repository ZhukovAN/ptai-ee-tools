REM start java -Xmx2g -Xms32m -XX:+UseConcMarkSweepGC -Dspring.main.lazy-initialization=true -jar ../target/ptai-integration-service-0.1-spring-boot.jar 10
start java -Xmx2g -Xms32m -XX:+UseConcMarkSweepGC -Dspring.main.lazy-initialization=true -Dspring.profiles.active=test -jar ../target/ptai-integration-service-0.1-spring-boot.jar 10
