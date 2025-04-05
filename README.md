# Blockchain CVSS Calculator

This calculator is a fork of <a href="https://gitlab-com.gitlab.io/gl-security/product-security/appsec/cvss-calculator/">GitLab's CVSS Calculator</a>, with changes made to be more relevant to Blockchain and Web3 systems.</a>.
          
The calculator is a simple [Vue.js](https://vuejs.org/) backed static web application that presents a series of questions that, when answered, are used to calculate a severity score using the Common Vulnerability Scoring System ([CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)).

## Running locally
The calculator is a static website, so all that is required is a way to serve the files on a local web server. [serve](https://npm.io/package/serve) is useful for this.

## Updating Vue
Remember to update the `vuedev` and `vueprod` variables in `build.sh` if updating the Vue framework. The `build.sh` script is run by CI when building the static site on GitLab to replace the Vue developer version with a minified and production optimized version.

## Updating CVSS

This version of the CVSS calculator uses JavaScript from https://www.first.org/cvss/v3.1/use-design#techdesign. If First.org release a new version, they might also release updated JavaScript at a similar location.

## Location

The Blockchain CVSS Calculator can be accessed at this address: https://github.com/0xCVH/blockchain-cvss-calculator
