# SecScanner2JUnit
[![PyPI version](https://badge.fury.io/py/secscanner2junit.svg)](https://badge.fury.io/py/secscanner2junit)

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/angrymeir/SecScanner2JUnit)

GitLab offers [security scanning and visualization](https://docs.gitlab.com/ee/user/application_security/) directly via and on their platform.  
One nice feature is direct insights on merge requests. However, this feature is only available with the Ultimate tier. To also use this feature on the free tier, one can build around it by taking the security tool output, converting it to the JUnit format, and uploading it as JUnit report.

To summarize, this tool is for you if:
- You use GitLab's free tier
- You use Gitlabs [security templates](https://docs.gitlab.com/ee/user/application_security/)
- You want to easily access security tool output in merge requests

If you are on the GitLabs Ultimate tier, just use their tooling! No need to mess up your `.gitlab-ci.yml` file. :smile:

## Which scanning types are supported?
All scanning types available under the free tier:
- Secret Scanning
- Static Application Security Testing
- Infrastructure as Code Scanning

## How to use?
Procedure:
1. Overwrite the existing job so that the report can be used by future jobs.  
2. Convert report
3. Upload converted report as junit report

**Example for Secret Scanning**  
This example can be used as is.
```yaml
stages:
  - test
  - convert
  
- include:
  - template: Security/Secret-Detection.gitlab-ci.yml
  
secret_detection:
  artifacts:
    paths:
      - gl-secret-detection-report.json
    when: always
    
secret_convert:
  stage: convert
  dependencies:
    - secret_detection
  script:
    - pip3 install SecScanner2JUnit
    - ss2ju secrets gl-secret-detection-report.json gl-secret-detection-report.xml
  artifacts:
    reports:
      junit: gl-secret-detection-report.xml
```

**Example for SAST**  
Since GitLab decides dynamically which scanners to use depending on project languages, it makes sense to first perform a testrun only including the template. This way one can see which jobs are executed and then overwrite them. 
```yaml
stages:
  - test
  - convert
  
- include:
  - template: Security/SAST.gitlab-ci.yml
  
semgrep-sast:
  after_script:
    - cp gl-sast-report.json gl-sast-semgrep-report.json
  artifacts:
    paths:
      - gl-sast-semgrep-report.json
    when: always

brakeman-sast:
  after_script:
    - cp gl-sast-report.json gl-sast-brakeman-report.json
  artifacts:
    paths:
      - gl-sast-brakeman-report.json
    when: always

semgrep-sast-convert:
  stage: convert
  dependencies:
    - semgrep-sast
  script:
    - pip3 install SecScanner2JUnit
    - ss2ju sast gl-sast-semgrep-report.json gl-sast-semgrep-report.xml
  artifacts:
    reports:
      junit: gl-sast-semgrep-report.xml
      
brakeman-sast-convert:
  stage: convert
  dependencies:
     - brakeman-sast
  script:
    - pip3 install SecScanner2JUnit
    - ss2ju sast gl-sast-brakeman-report.json gl-sast-brakeman-report.xml
  artifacts:
    reports:
      junit: gl-sast-brakeman-report.xml

```

## Future Plans
- [ ] Implement IaC Scanning
