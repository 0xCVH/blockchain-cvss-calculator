# CVSS Calculator

This calculator is used to calculate bounties for vulnerabilities reported to GitLab's [Bug Bounty Program on HackerOne](https://hackerone.com/gitlab). The calculator is a simple [Vue.js](https://vuejs.org/) backed static web application that presents a series of questions that, when answered, are used to calculate a severity score using the Common Vulnerability Scoring System ([CVSS 3.0](https://www.first.org/cvss/v3.0/specification-document)). The calculator will also calculate a suggested bug bounty reward based on the CVSS score and GitLab's reward ranges in order to have more consistency with both our severity rating and bug bounty rewards.

## Running locally
The calculator is a static website, so all that is required is a way to serve the files on a local web server. [serve](https://npm.io/package/serve) is useful for this.

## Updating Vue
Remember to update the `vuedev` and `vueprod` variables in `build.sh` if updating the Vue framework. The `build.sh` script is run by CI when building the static site on GitLab to replace the Vue developer version with a minified and production optimized version.
