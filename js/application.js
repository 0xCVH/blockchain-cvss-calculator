const EventBus = new Vue();

/**
 * QuestionAnswer represents the answers to a question.
 *
 * QuestionAnwer is used within the Question template to render the possible answers to a question.
 */
Vue.component('QuestionAnswer', {
  props: {
    answer: {
      type: Object
    },
    callback: {
      type: Function
    }
  },
  template: '#answer-template'
});

/**
 * Question represents a question.
 */
Vue.component('Question', {
  props: ['question'],
  template: '#question-template'
});

/**
 * Examples represents the examples that answers can have.
 *
 * Examples is used within the Answer template.
 */
Vue.component('Examples', {
  props: ['examples'],
  template: '#examples-template'
});

/**
 * SkipQuestions controls the feature for skipping questions by entering a CVSS token.
 *
 * The component is a clickable link that will present an input field on click.
 */
Vue.component('skipquestions', {
  data () {
    return {
      cvssVector: '',
      validCvssVector: false,
      formShown: false
    }
  },
  template: '#skip-questions-template',
  methods: {
    /**
     * Shows the CVSS vector input form and hides the link.
     *
     * @param {Object} e The click event.
     */
    showForm: function (e) {
      e.preventDefault();
      this.formShown = true;
    },
    /**
     * Validates the CVSS vector entered into the form and enables the submit button if valid.
     *
     * Accepts CVSS 3.X vector strings with and without the version identifier. If the version
     * identifier is missing, 3.1 will be automatically prepended to the entered CVSS vector.
     */
    validateCvssVector: function () {
      // v3.0 (deprecated)
      if (CVSS.vectorStringRegex_30.test(this.cvssVector)) {
        return true;
      }

      // v3.1
      if (CVSS31.vectorStringRegex_31.test(this.cvssVector)) {
        return true;
      }

      // No version, fallback to 3.1
      if (CVSS31.vectorStringRegex_31.test(`${CVSS31.CVSSVersionIdentifier}/${this.cvssVector}`)) {
        this.cvssVector = `${CVSS31.CVSSVersionIdentifier}/${this.cvssVector}`;
        return true;
      }
      return false;
    },
    /**
     * Redirects the browser to the CVSS score page by altering the location hash/fragement to
     * trigger the score route.
     */
    showScore: function () {
      window.location.hash = `#vector=${this.cvssVector}`;
    }
  },
  watch: {
    /**
     * Validate the CVSS vector every time it's changed.
     */
    cvssVector: function () {
      this.validCvssVector = this.validateCvssVector();
    }
  }
});

/**
 * Definitions allows all metric scoring definitions
 * to be viewed.
 *
 */
Vue.component('Definitions', {
  template: '#definitions-template',
  data () {
    return {
      definitionsShown: true,
      definitions: [],
    }
  },
  methods: {
    /**
     * Toggles whether we show the definitions section.
     *
     * @param {Object} e The click event.
     */
    toggleDefinitions: function (e) {
      e.preventDefault();
      this.definitionsShown = !this.definitionsShown ;
    },
    loadDefinitions: function (e) {
      // If we haven't already gathered the definitions
      if (!!this.definitions) {
        // Iterate over the calculator's questions
        for (let key in this.$parent.questions) {
          question = this.$parent.questions[key];

          for (let answer of question.answers) {
            // Only look at questions that result in a CVSS Metric Value
            if (typeof answer.cvss_metric !== 'undefined') {
              // Add it to the list
              this.definitions.push({
                metric_value: answer.cvss_metric,
                extra: answer.extra,
                examples: answer.examples,
                mitigations: answer.mitigations
              })
            }
          }
        }
      }
    }
  },
  mounted() {
    this.loadDefinitions();
  }
});
/**
 * Explanations allows all metric scoring definitions
 * to be viewed.
 *
 */
Vue.component('Explanations', {
  template: '#explanations-template',
  // props: {
  //   cvssVector: {
  //     type: String,
  //     required: false,
  //   }
  // },
  data () {
    return {
      metrics: [],
      cvssVector: '',
      cvssScore: '',
      severity: ''
    }
  },
  // when created, listen for the EventBus trigger method called "updateExplanations"
  created() {
    EventBus.$on('updateExplanations', (vector) => this.updateExplanations(vector));
  },
  methods: {
    updateExplanations: function(vector) {
      this.cvssVector = vector;
      this.calculateCVSS();
      this.loadExplanations();
    },
    loadExplanations: function () {
      // Reset metrics so we always start empty
      this.metrics = [];

      var showAll = false;
      // If a vector isn't present, show all explanations
      if (typeof this.cvssVector !== 'string' || this.cvssVector.length === 0) {
        showAll = true;
      }
      var scoreCardInstance = new scoreCard();

      // Iterate over the calculator's questions
      for (let key in this.$parent.questions) {
        question = this.$parent.questions[key];

        for (let answer of question.answers) {
          // Only look at questions that result in a CVSS Metric Value
          if (typeof answer.cvss_metric !== 'undefined') {
            // Only add to the table when it's present in the vector
            if (showAll || (this.cvssVector.indexOf('/'+answer.cvss_metric) >= 0)) {
              // Split answer.cvss_metric on :
              var [metric, score] = answer.cvss_metric.split(':');

              var humanMetric = scoreCardInstance.$data.humanMetrics[metric];
              var humanScore = scoreCardInstance.$data.humanScores[metric][score];

              this.metrics.push({
                metric_value: answer.cvss_metric,
                human_metric: humanMetric + ' - ' + humanScore,
                extra: answer.extra,
                examples: answer.examples,
                mitigations: answer.mitigations,

              })
            }
          }
        }
      }
    },
    /**
     * Calculates the CVSS score from the metrics.
     */
    calculateCVSS: function () {
      var score;

      if (CVSS.vectorStringRegex_30.test(this.cvssVector)) {
        score = CVSS.calculateCVSSFromVector(this.cvssVector);
        this.oldCVSSVersion = true;
      } else if (CVSS31.vectorStringRegex_31.test(this.cvssVector)) {
        score = CVSS31.calculateCVSSFromVector(this.cvssVector);
        this.oldCVSSVersion = false;
      } else {
        console.warn('Unknown CVSS version: ' + this.cvssVector);
      }

      this.cvssScore = score.baseMetricScore;
      this.severity = score.baseSeverity;
    },
  },
  mounted() {
    this.loadExplanations();
  }
});

/**
 * ScoreCard represents a single CVSS metric which is rendered in ScoreModal for each metric.
 */
var scoreCard = Vue.component('ScoreCard', {
  props: ['metric', 'score'],
  template: '#score-card-template',
  data () {
    return {
      severityHigh: false,
      severityMedium: false,
      severityLow: false,
      humanFriendlyScore: undefined,
      tooltip: null,
      humanMetrics: {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        PR: 'Privileges Required',
        UI: 'User Interaction',
        S: 'Scope',
        C: 'Confidentiality',
        I: 'Integrity',
        A: 'Availability',
      },
      metricExplanations: {
        AV: {
          N: 'The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers). An example of a network attack is an attacker causing a denial of service (DoS) by sending a specially crafted TCP packet across a wide area network (e.g., CVE‑2004‑0230).',
          A: 'The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment (e.g., CVE‑2013‑6014).',
          L: 'The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <ul><li>the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or</li><li>the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).</li></ul>',
          P: 'The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA).',
        },
        AC: {
          L: 'Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.',
          H: `A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may depend on an attacker overcoming any of the following conditions: <ul><li>The attacker must gather knowledge about the environment in which the vulnerable target/component exists. For example, a requirement to collect details on target configuration settings, sequence numbers, or shared secrets.</li><li>The attacker must prepare the target environment to improve exploit reliability. For example, repeated exploitation to win a race condition, or overcoming advanced exploit mitigation techniques.</li><li>The attacker must inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).</li></ul>`,
        },
        PR: {
          N: 'The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack.',
          L: 'The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.',
          H: 'The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.',
        },
        UI: {
          N: 'The vulnerable system can be exploited without interaction from any user.',
          R: 'Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.',
        },
        S: {
          U: 'An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.',
          C: 'An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.',
        },
        C: {
          H: `There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.`,
          L: 'There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.',
          N: 'There is no loss of confidentiality within the impacted component.',
        },
        I: {
          H: 'There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.',
          L: 'Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.',
          N: 'There is no loss of integrity within the impacted component.',
        },
        A: {
          H: 'There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).',
          L: 'Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.',
          N: 'There is no impact to availability within the impacted component.',
        },
      },
      humanScores: {
        AV: {
          N: 'Network',
          A: 'Adjacent',
          L: 'Local',
          P: 'Physical'
        },
        AC: {
          L: 'Low',
          H: 'High'
        },
        PR: {
          N: 'None',
          L: 'Low',
          H: 'High'
        },
        UI: {
          N: 'None',
          R: 'Required'
        },
        S: {
          U: 'Unchanged',
          C: 'Changed'
        },
        C: {
          N: 'None',
          L: 'Low',
          H: 'High'
        },
        I: {
          N: 'None',
          L: 'Low',
          H: 'High'
        },
        A: {
          N: 'None',
          L: 'Low',
          H: 'High'
        }
      },
    }
  },
  methods: {
    /**
     * Determines the severity (high, medium, low) of the CVSS metric.
     */
    determineSeverity: function () {
      if (this.metric === 'AV' && this.score === 'N') { this.severityHigh = true }
      else if (this.metric === 'AV' && this.score === 'A') { this.severityMedium = true }
      else if (this.metric === 'AC' && this.score === 'L') { this.severityHigh = true }
      else if (this.metric === 'UI' && this.score === 'N') { this.severityHigh = true }
      else if (this.metric === 'PR' && this.score === 'N') { this.severityHigh = true }
      else if (this.metric === 'PR' && this.score === 'L') { this.severityMedium = true }
      else if (this.metric === 'S' && this.score === 'C')  { this.severityHigh = true }
      else if (this.metric === 'C' && this.score === 'H')  { this.severityHigh = true }
      else if (this.metric === 'C' && this.score === 'L')  { this.severityMedium = true }
      else if (this.metric === 'I' && this.score === 'H')  { this.severityHigh = true }
      else if (this.metric === 'I' && this.score === 'L')  { this.severityMedium = true }
      else if (this.metric === 'A' && this.score === 'H')  { this.severityHigh = true }
      else if (this.metric === 'A' && this.score === 'L')  { this.severityMedium = true }
      else { this.severityLow = true }
    },
    /**
     * Translates the shorthand metric scores to a more human friendly representation.
     */
    scoreToHumanFriendly: function () {
      this.humanFriendlyScore = this.humanScores[this.metric][this.score];
    }
  },
  mounted() {
    this.determineSeverity();
    this.scoreToHumanFriendly();
    this.tooltip = new bootstrap.Popover(this.$refs.card, {
      title: this.humanMetrics[this.metric],
      content: this.metricExplanations[this.metric][this.score],
      placement: 'bottom',
      html: true,
    });
  }
});

/**
 * ScoreModal represents the final modal screen which presents the CVSS score and suggested bounty.
 */
var ScoreModal = Vue.component('ScoreModal', {
  props: {
    cvssVector: {
      type: String,
      required: true,
    },
    bountyRange: {
      type: String,
      default: function () {
        return 'new';
      },
    },
    oldCVSSVersion: false,
  },
  template: '#score-modal-template',
  data () {
    return {
      cvssMetrics: {
        AV: undefined,
        AC: undefined,
        PR: undefined,
        UI: undefined,
        S: undefined,
        C: undefined,
        I: undefined,
        A: undefined,
      },
      cvssScore: 0.0,
      severity: undefined,
      severityCritical: false,
      severityHigh: false,
      severityMedium: false,
      severityLow: false,
      suggestedBounty: 0,
      bountyRanges: {
        old: {
          Critical: {
            minScore: 9.0,
            maxScore: 10.0,
            minBounty: 10000,
            maxBounty: 20000
          },
          High: {
            minScore: 7.0,
            maxScore: 8.9,
            minBounty: 3000,
            maxBounty: 10000
          },
          Medium: {
            minScore: 4.0,
            maxScore: 6.9,
            minBounty: 500,
            maxBounty: 1500
          },
          Low: {
            minScore: 0.1,
            maxScore: 3.9,
            minBounty: 50,
            maxBounty: 500
          }
        },
        new: {
          Critical: {
            minScore: 9.0,
            maxScore: 10.0,
            minBounty: 20000,
            maxBounty: 35000
          },
          High: {
            minScore: 7.0,
            maxScore: 8.9,
            minBounty: 5000,
            maxBounty: 15000
          },
          Medium: {
            minScore: 4.0,
            maxScore: 6.9,
            minBounty: 1000,
            maxBounty: 2500
          },
          Low: {
            minScore: 0.1,
            maxScore: 3.9,
            minBounty: 100,
            maxBounty: 750
          }
        }
      }
    }
  },
  beforeMount() {
    this.populateCvssMetricsFromVector(this.cvssVector);
    this.calculateCVSS();
    this.calculateSuggestedBounty();
    this.determineSeverity();
  },
  methods: {
    /**
     * Calculates the CVSS score from the metrics.
     */
    calculateCVSS: function () {
      var score;

      if (CVSS.vectorStringRegex_30.test(this.cvssVector)) {
        score = CVSS.calculateCVSSFromVector(this.cvssVector);
        this.oldCVSSVersion = true;
      } else if (CVSS31.vectorStringRegex_31.test(this.cvssVector)) {
        score = CVSS31.calculateCVSSFromVector(this.cvssVector);
        this.oldCVSSVersion = false;
      } else {
        console.warn('Unknown CVSS version: ' + this.cvssVector);
      }

      this.cvssScore = score.baseMetricScore;
      this.severity = score.baseSeverity;
    },
    /**
     * Parses the CVSS vector string and populates the metrics with correct values.
     *
     * @param {string} vector The CVSS vector string
     */
    populateCvssMetricsFromVector: function (vector) {
      var metrics = vector.substring(CVSS31.CVSSVersionIdentifier.length).split("/");
      for (const m of metrics) {
        if (m === "") {
          continue;
        }
        var metricAndScore = m.split(':');
        if (metricAndScore[0] in this.cvssMetrics) {
          this.cvssMetrics[metricAndScore[0]] = metricAndScore[1];
        }
      }
    },
    /**
     * Determines the severity (critical, high, medium, low) of the CVSS score.
     */
    determineSeverity: function () {
      switch (this.severity) {
        case 'Critical':
          this.severityCritical = true;
          break;
        case 'High':
          this.severityHigh = true;
          break;
        case 'Medium':
          this.severityMedium = true;
          break;
        case 'Low':
        case 'None':
          this.severityLow = true;
        }
    },
    /**
     * Calculates the suggested bounty based on the CVSS score and populates the suggestBounty data
     * attribute with the number with pretty formatting.
     */
    calculateSuggestedBounty: function () {
      range = this.bountyRanges[this.bountyRange][this.severity];
      bounty = this.getBounty(this.cvssScore, range.minScore, range.maxScore, range.minBounty, range.maxBounty);
      this.suggestedBounty = this.formatBounty(bounty);
    },
    /**
     * Calculates the suggested bounty based on the CVSS score.
     *
     * Logic for this method is borrowed from Shopify's bounty calculator. Thanks! ;)
     *
     * @param {number} score     The CVSS score.
     * @param {number} minScore  The minimum score.
     * @param {number} maxScore  The maximum score.
     * @param {number} minBounty The minimum bounty.
     * @param {number} maxBounty The maximum bounty.
     * @return {number} Suggested bounty.
     */
    getBounty: function (score, minScore, maxScore, minBounty, maxBounty) {
      //Sets bounty for severity
      bountyRange = maxBounty - minBounty;
      //Sets score range for severity
      scoreRange = maxScore - minScore;
      //Sets score above lowest range
      score = score - minScore;
      //Sets score as a percentage of range
      scorePercentage = score / scoreRange;
      //Multiplies score percentage by bounty range to find percentage
      bountyPercentage = scorePercentage * bountyRange;
      //Adds pay percentage to minimum bounty amount
      return bountyPercentage + minBounty;
    },
    /**
     * Formats the bounty as USD currency.
     *
     * @param {number} bounty amount.
     * @return {string} Formatted bounty amount.
     */
    formatBounty: function (bounty) {
      bounty = this.roundUp(bounty, 10);
      var formatter = new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
      });
      return formatter.format(bounty);
    },
    /**
     * Rounds a number up to the nearest whole number.
     *
     * @param {Number|String} num Number to round.
     * @param {Number} precision Whole number to round to (10, 100, 1000).
     * @return {Number}
     */
    roundUp: function (num, precision) {
      num = parseFloat(num);
      if (!precision) {
        return num;
      }
      return (Math.ceil(num / precision) * precision);
    },
    /**
     * Returns the document's location without the trailing `/#` part
     *
     * @return {String}
     */
    locationWithoutFragment: function() {
      return document.location.href.replace(/\/?#.*$/, '');
    },
    /**
     * Copies a Markdown formatted link to the clipboard with following format:
     *
     *     [<CVSS vector>](<url>) (<CVSS score> / <severity> / $<suggested bounty> / <bounty range name> bounty range)
     *
     * @param {Object} e The click event.
     */
    copyMarkdownLinkToClipboard: function (e) {
      e.preventDefault();
      this.copyToClipboard(`[${this.cvssVector}](${this.locationWithoutFragment()}/#vector=${this.cvssVector}) (${this.cvssScore} ${this.severity} / ${this.suggestedBounty})`);
      this.$refs.btnCopyMarkdownLink.innerText = "Copied URL to clipboard!";
    },
    /**
     * Copies the score URL to the clipboard.
     *
     * @param {Object} e The click event.
     */
    copyURLToClipboard: function (e) {
      e.preventDefault();
      this.copyToClipboard(`${this.locationWithoutFragment()}/#vector=${this.cvssVector}`);
      this.$refs.btnCopyUrl.innerText = "Copied URL to clipboard!";
    },
    /**
     * Copies the CVSS vector to the clipboard.
     *
     * @param {Object} e The click event.
     */
    copyVectorToClipboard: function (e) {
      e.preventDefault();
      this.copyToClipboard(this.cvssVector);
      this.$refs.btnCopyVector.innerText = "Copied vector to clipboard!";
    },
    /**
     * Copies text the clipboard.
     *
     * Temporarily adds an input element with the given text to the DOM in order to select and copy
     * the content, and is then immediately removed.
     *
     * @param {string} text The text to copy to the clipboard.
     */
    copyToClipboard: function (text) {
      el = document.createElement('input');
      el.value = text;
      this.$el.appendChild(el);
      el.select();
      document.execCommand('copy');
      this.$el.removeChild(el);
    },
    /**
     * Changes the active bounty range when a bounty range is clicked.
     *
     * @param {Object} e The click event.
     */
    changeBountyRange: function (e) {
      e.preventDefault();
      const range = e.target.getAttribute('data-bounty-range')
      if (!(range in this.bountyRanges)) {
        this.bountyRange = 'old';
      } else {
        this.bountyRange = range;
      }
      this.calculateSuggestedBounty();
    }
  }
});

var app = new Vue({
  el: '#app',
  data: {
    cvssMetrics: {
      AV: undefined,
      AC: undefined,
      PR: undefined,
      UI: undefined,
      S: undefined,
      C: undefined,
      I: undefined,
      A: undefined,
    },
    bountyRange: 'new',
    current_route: window.location.hash,
    current_question: 'attack_vector_1',
    questions: {
      attack_vector_1: {
        title: 'Attack Vector',
        question: 'Does the attacker exploit the vulnerable component (e.g., smart contract, node software, blockchain client) via the network stack?',
        answers: [{
          answer: 'Yes',
          onSelect: () => { this.app.goToPage('attack_vector_2'); }
        }, {
          answer: 'No',
          onSelect: () => { this.app.goToPage('attack_vector_3'); }
        }]
      },
      attack_vector_2: {
        title: 'Attack Vector',
        question: 'Can the vulnerability be exploited from across a router (OSI layer 3 network), i.e., from anywhere on the internet or a permissionless blockchain network?',
        answers: [{
          answer: 'Yes',
          extra: 'Vulnerability is exploitable using the public internet or a permissionless blockchain network. For smart contracts, this could mean an attacker can call the contract from any node on the network. For node software, it could mean the node is publicly reachable and can be exploited remotely.',
          examples: [
            'Attack triggered by sending a malicious transaction to a public blockchain.',
            'Attack triggered by sending a specially-crafted message to a publicly-exposed node (e.g., geth).'
          ],
          mitigations: [
            'Using firewall rules to limit inbound connections to your node software.',
            'Ensuring smart contracts are audited and not publicly callable for critical functions if not intended.'
          ],
          cvss_metric: 'AV:N',
          onSelect: () => { this.app.cvssMetrics.AV = 'N'; this.app.goToPage('attack_complexity_1'); }
        }, {
          answer: 'No',
          extra: 'Attack must be launched from a limited physical or logical network distance (e.g. a private blockchain or local network).',
          cvss_metric: 'AV:A',
          onSelect: () => { this.app.cvssMetrics.AV = 'A'; this.app.goToPage('attack_complexity_1'); }
        }]
      },
      attack_vector_3: {
        title: 'Attack Vector',
        question: 'Does the attacker require physical access to the target?',
        answers: [{
          answer: 'Yes',
          extra: 'Attacker requires physical access to the vulnerable component (e.g., direct access to a hardware wallet or a node\'s physical machine).',
          cvss_metric: 'AV:P',
          onSelect: () => { this.app.cvssMetrics.AV = 'P'; this.app.goToPage('attack_complexity_1'); }
        }, {
          answer: 'No',
          extra: 'Attack is committed through local application or local network vulnerabilities (e.g. local privilege escalation on a node running the software, or the attacker can log in locally to the machine hosting the node).',
          examples: [
            'A malicious or compromised node operator who already has local shell access to the server running geth or lighthouse.'
          ],
          cvss_metric: 'AV:L',
          onSelect: () => { this.app.cvssMetrics.AV = 'L'; this.app.goToPage('attack_complexity_1'); }
        }]
      },
      attack_complexity_1: {
        title: 'Attack Complexity',
        question: 'Can the attacker exploit the vulnerability at will, without relying on luck or complex conditions?',
        answers: [{
          answer: 'Yes',
          extra: 'Attacker can exploit the vulnerability at any time, reliably. No unusual conditions or dependencies.',
          examples: [
            'Calling a smart contract function that fails to check proper permissions, leading to immediate exploitation.',
            'Sending a specially crafted peer-to-peer (P2P) message that always triggers the bug in node software.',
            'A simple guessable transaction payload or hash that can be used for re-entrancy attacks in a smart contract.'
          ],
          mitigations: [
            'Disabling certain blockchain features or functions can sometimes increase complexity (or eliminate the vulnerability).',
            'Implementing proper permission checks and security patterns in smart contracts (e.g., re-entrancy guards).'
          ],
          cvss_metric: 'AC:L',
          onSelect: () => { this.app.cvssMetrics.AC = 'L'; this.app.goToPage('privileges_required_1'); }
        }, {
          answer: 'No',
          extra: 'Successful attack depends on conditions beyond the attacker\'s direct control (e.g., certain network states, specific block timing, or chain re-org conditions).',
          examples: [
            'Exploit requires a specific timing related to block production that can\'t always be reproduced (e.g., front-running scenarios).',
            'Exploitation requires the blockchain or client to be in a particular discouraged or non-default configuration.',
            'The victim node or contract must be in a certain mode that is not typically enabled by default.'
          ],
          mitigations: [
            'Use recommended software configurations and defaults.',
            'Avoid enabling experimental or non-standard client modes unless necessary and properly secured.'
          ],
          cvss_metric: 'AC:H',
          onSelect: () => { this.app.cvssMetrics.AC = 'H'; this.app.goToPage('privileges_required_1'); }
        }]
      },
      privileges_required_1: {
        title: 'Privileges Required',
        question: 'Must the attacker be authorized or have special privileges within the blockchain environment (e.g., specialized roles or permissions) prior to the attack?',
        answers: [{
          answer: 'Yes',
          onSelect: () => { this.app.goToPage('privileges_required_2'); }
        }, {
          answer: 'No',
          examples: [
            'Permission issues allowing an unauthenticated user to invoke a privileged smart contract function.',
            'No authentication needed to exploit the node or chain (e.g., a DoS vulnerability in the P2P layer).'
          ],
          mitigations: [
            'Restrict public access to nodes whenever possible (firewalls, private networks).',
            'Use on-chain or off-chain checks for contract permissions.'
          ],
          cvss_metric: 'PR:N',
          onSelect: () => { this.app.cvssMetrics.PR = 'N'; this.app.goToPage('user_interaction_1'); }
        }]
      },
      privileges_required_2: {
        title: 'Privileges Required',
        question: 'Are administrator (e.g., chain owner, privileged contract role) or \'high\' privileges required to exploit the vulnerability?',
        answers: [{
          answer: 'Yes',
          extra: 'The attack requires high-level or administrative privileges in the blockchain ecosystem. For instance, only a privileged role in a smart contract or node admin rights can trigger the flaw.',
          examples: [
            'Requires admin/owner role in the smart contract for critical functions.',
            'Requires local or root access to the server running the blockchain node.'
          ],
          mitigations: [
            'Restrict privileged roles to trusted parties only.',
            'Use multi-signature or DAO governance for critical changes, limiting direct admin power.'
          ],
          cvss_metric: 'PR:H',
          onSelect: () => { this.app.cvssMetrics.PR = 'H'; this.app.goToPage('user_interaction_1'); }
        }, {
          answer: 'No',
          extra: 'An authenticated user or a user with a non-critical role can carry out the attack. For example, an attacker needs a normal wallet address or membership in a private consortium chain but not a special admin key.',
          examples: [
            'Any participant with a valid blockchain address can create a transaction that exploits a vulnerability in the contract logic.',
            'An authenticated node on a permissioned network can exploit a bug that affects consensus, but does not require highest-level privileges.'
          ],
          mitigations: [
            'For permissioned blockchains, limit membership and monitor node behavior.',
            'Enforce principle of least privilege in smart contract roles.'
          ],
          cvss_metric: 'PR:L',
          onSelect: () => { this.app.cvssMetrics.PR = 'L'; this.app.goToPage('user_interaction_1'); }
        }]
      },
      user_interaction_1: {
        title: 'User Interaction',
        question: 'Does the attacker require some other user (or node) to perform an action (e.g., confirm a transaction, sign a message) for the exploit to succeed?',
        answers: [{
          answer: 'Yes',
          extra: 'Successful attack requires user (or another node/operator) interaction.',
          examples: [
            'A phishing scenario where a user signs a transaction that triggers a hidden malicious contract call.',
            'A victim must connect to a malicious node or accept some malicious on-chain action (e.g. setting a certain contract parameter) before exploitation is complete.'
          ],
          cvss_metric: 'UI:R',
          onSelect: () => { this.app.cvssMetrics.UI = 'R'; this.app.goToPage('scope_1'); }
        }, {
          answer: 'No',
          extra: 'Attack can be accomplished without any additional user or node interaction (e.g. purely network-based or automatically triggered in block production).',
          examples: [
            'A vulnerability in node consensus logic that can be exploited by simply broadcasting a malformed block or transaction with no user involvement.'
          ],
          cvss_metric: 'UI:N',
          onSelect: () => { this.app.cvssMetrics.UI = 'N'; this.app.goToPage('scope_1'); }
        }]
      },
      scope_1: {
        title: 'Scope',
        question: 'Can the attacker affect a component (on-chain or off-chain) whose authority is different than the vulnerable component?',
        answers: [{
          answer: 'Yes',
          extra: 'Impact extends beyond the vulnerable component, e.g. bridging to external systems, or accessing off-chain services and credentials.',
          examples: [
            'A smart contract that can read or manipulate external oracles, affecting real-world data.',
            'A node exploit that gives the attacker access to host-level credentials or other services on the same machine.',
            'A vulnerability in bridging software that affects another blockchain or system.'
          ],
          mitigations: [
            'Isolate critical off-chain services from on-chain interactions wherever possible.',
            'Restrict oracles and bridging contracts to trusted or well-audited providers.'
          ],
          cvss_metric: 'S:C',
          onSelect: () => { this.app.cvssMetrics.S = 'C'; this.app.goToPage('confidentiality_impact_1'); }
        }, {
          answer: 'No',
          extra: 'Impact is localized to the exploited smart contract or node software itself without crossing trust boundaries.',
          examples: [
            'A bug that allows unauthorized function calls within the same contract or node but does not affect other systems or on-chain components outside its scope.'
          ],
          cvss_metric: 'S:U',
          onSelect: () => { this.app.cvssMetrics.S = 'U'; this.app.goToPage('confidentiality_impact_1'); }
        }]
      },
      confidentiality_impact_1: {
        title: 'Confidentiality Impact',
        question: 'Is there any impact to confidentiality (e.g., exposure of private keys, sensitive on-chain data, node logs)?',
        answers: [{
          answer: 'Yes',
          onSelect: () => { this.app.goToPage('confidentiality_impact_2'); }
        }, {
          answer: 'No',
          extra: 'No confidential or sensitive information is disclosed.',
          cvss_metric: 'C:N',
          onSelect: () => { this.app.cvssMetrics.C = 'N'; this.app.goToPage('integrity_impact_1'); }
        }]
      },
      confidentiality_impact_2: {
        title: 'Confidentiality Impact',
        question: 'Can the attacker obtain all, or a critical subset, of information from the impacted component (like private keys, entire node data, or privileged contract variables)?',
        answers: [{
          answer: 'Yes',
          extra: 'All information is disclosed to the attacker, or a particularly critical piece of data is compromised.',
          examples: [
            'Full read access to private keys or entire node’s sensitive data directory.',
            'Exfiltration of seed phrases stored in memory or logs.',
            'Reading privileged private variables in a smart contract that reveal crucial financial data.'
          ],
          cvss_metric: 'C:H',
          onSelect: () => { this.app.cvssMetrics.C = 'H'; this.app.goToPage('integrity_impact_1'); }
        }, {
          answer: 'No',
          extra: 'Some information can be obtained, but attacker does not have full or unlimited read access, or only minor private data is exposed.',
          examples: [
            'Access to small or non-critical amounts of data, such as partial contract state that was supposed to be hidden.',
            'Exposure of public node logs that offer limited informational value but not keys or critical secrets.'
          ],
          cvss_metric: 'C:L',
          onSelect: () => { this.app.cvssMetrics.C = 'L'; this.app.goToPage('integrity_impact_1'); }
        }]
      },
      integrity_impact_1: {
        title: 'Integrity Impact',
        question: 'Is there any impact to the integrity of the system or data (e.g., tampering with smart contract state, forging transactions)?',
        answers: [{
          answer: 'Yes',
          onSelect: () => { this.app.goToPage('integrity_impact_2'); }
        }, {
          answer: 'No',
          extra: 'No integrity loss (e.g., read-only exposure without the ability to modify data).',
          cvss_metric: 'I:N',
          onSelect: () => { this.app.cvssMetrics.I = 'N'; this.app.goToPage('availability_impact_1'); }
        }]
      },
      integrity_impact_2: {
        title: 'Integrity Impact',
        question: 'Can the attacker modify all or critical data (e.g., entire contract state, forging blocks, altering node consensus)?',
        answers: [{
          answer: 'Yes',
          extra: 'Attacker can modify any information at any time, or specifically critical/privileged data.',
          examples: [
            'Attacker can rewrite on-chain records or forge entire blocks in the chain consensus.',
            'A smart contract exploit that grants the attacker unlimited minting capabilities or administrative control of critical functions.',
            'A node software bug enabling unauthorized changes to the ledger’s state.'
          ],
          cvss_metric: 'I:H',
          onSelect: () => { this.app.cvssMetrics.I = 'H'; this.app.goToPage('availability_impact_1'); }
        }, {
          answer: 'No',
          extra: 'Some data can be altered, but not all or not the most critical data. Attack may allow partial or situational modifications.',
          examples: [
            'Limited ability to update a small subset of contract state variables but not fully control the contract.',
            'A node exploit letting attacker change minor configuration details but not the ledger itself.'
          ],
          cvss_metric: 'I:L',
          onSelect: () => { this.app.cvssMetrics.I = 'L'; this.app.goToPage('availability_impact_1'); }
        }]
      },
      availability_impact_1: {
        title: 'Availability Impact',
        question: 'Is there any impact to the availability of a resource (e.g. node crashing, smart contract becoming unusable, DoS on the network)?',
        answers: [{
          answer: 'Yes',
          extra: 'The vulnerability can reduce or completely deny access to the blockchain component or node functionality.',
          onSelect: () => { this.app.goToPage('availability_impact_2'); }
        }, {
          answer: 'No',
          extra: 'No availability impact.',
          cvss_metric: 'A:N',
          onSelect: () => { this.app.cvssMetrics.A = 'N'; this.app.goToScore(); }
        }]
      },
      availability_impact_2: {
        title: 'Availability Impact',
        question: 'Can the attacker completely deny access to the affected component or disrupt the blockchain network/consensus significantly?',
        answers: [{
          answer: 'Yes',
          extra: 'Access is denied to a critical resource or the entire system is severely affected (e.g., chain halts, node crashes persistently).',
          examples: [
            'A DoS exploit that causes all nodes running a certain client version to crash, halting the network.',
            'A block-level vulnerability that prevents block production or finalization across the network.'
          ],
          cvss_metric: 'A:H',
          onSelect: () => { this.app.cvssMetrics.A = 'H'; this.app.goToScore(); }
        }, {
          answer: 'No',
          extra: 'Reduced performance or partial disruption to some nodes or smart contracts, but not a total system-wide denial of service.',
          examples: [
            'A minor or localized denial of service that makes some contracts temporarily unusable or some nodes slow to sync.',
            'Only a subset of validators or block producers are impacted; network continues but less efficiently.'
          ],
          cvss_metric: 'A:L',
          onSelect: () => { this.app.cvssMetrics.A = 'L'; this.app.goToScore(); }
        }]
      }
    }
  },
  methods: {
    validCVSS: function (vector) {
      return CVSS.vectorStringRegex_30.test(vector) || CVSS31.vectorStringRegex_31.test(vector);
    },
    /**
     * Renders a question with the given key.
     *
     * @param {string} key The question's key.
     */
    showQuestion: function (key) {
      this.current_question = this.questions[key];
    },
    /**
     * Determines which page to display based on the page hash / fragment.
     *
     * If the fragment is unknown or empty, the first attack vector question is rendered.
     *
     * @param {string} fragment The page fragment / hash without the leading '#'
     */
    showPageFromFragment: function (fragment) {
      // Show first question if fragment is empty.
      if (fragment === "") {
        this.showQuestion('attack_vector_1');
        return;
      }

      // Show score if fragment is a CVSS vector string.
      const key = fragment.substring(1);
      if (this.validCVSS(key)) {
        this.showQuestion('attack_vector_1');
        this.cvssVector = key;
        this.populateCvssMetricsFromVector(this.cvssVector);
        this.showScore();
        return;
      }

      // Show question if fragment matches a question key.
      if (key in this.questions) {
        this.showQuestion(key);
        return;
      }

      // Show score if fragment matches `vector=<cvss vector>&range=<range>` URL param string.
      const urlParams = new URLSearchParams(key);
      if (urlParams.has('vector')) {
        this.cvssVector = urlParams.get('vector');
        if (this.validCVSS(this.cvssVector)) {
          this.populateCvssMetricsFromVector(this.cvssVector);
          if (urlParams.has('range')) {
            this.bountyRange = urlParams.get('range');
          }
          this.showScore();
          return;
        } else {
          console.warn("Invalid / unsupported CVSS:", this.cvssVector)
        }
      }

      // Explain score if fragment matches `explain=<cvss vector>` URL param string.
      if (urlParams.has('explain')) {
        this.cvssVector = urlParams.get('explain');
        if (this.validCVSS(this.cvssVector)) {
          console.log("Explain", this.cvssVector);
          EventBus.$emit('updateExplanations', this.cvssVector);
          return;
        } else {
          console.warn("Invalid / unsupported CVSS:", this.cvssVector)
        }
      }

      this.showQuestion('attack_vector_1');
    },
    /**
     * Modifies the document location to point at the given page fragment / hash to trigger the
     * routing.
     *
     * @param {string} fragment The page fragement / hash without the leading '#'
     */
    goToPage: function (fragment) {
      window.location.hash = `#${fragment}`;
    },
    /**
     * Modifies the document location to point at the page fragment / hash to show the score page
     * for the current CVSS metrics.
     */
    goToScore: function () {
      const cvssVector = this.cvssMetricsToVector(this.cvssMetrics);
      window.location.hash = `#vector=${cvssVector}`;
    },
    /**
     * Renders the CVSS score page / modal with the current CVSS metrics.
     */
    showScore: function () {
      const cvssVector = this.cvssMetricsToVector(this.cvssMetrics);
      let modalInstance = new ScoreModal({
        propsData: { cvssVector: cvssVector, bountyRange: this.bountyRange }
      });
      modalInstance.$mount();
      this.$el.appendChild(modalInstance.$el);
      let modal = new bootstrap.Modal(modalInstance.$el);
      modalInstance.$el.addEventListener('hidden.bs.modal', (event) => {
        window.location.hash = "";
      });
      modal.show();
    },
    /**
     * Converts the given metrics object to a CVSS 3.1 vector string.
     *
     * @param {Object} metrics
     * @return {string} The CVSS 3.x vector string.
     */
    cvssMetricsToVector: function (metrics) {
      var vector = '';
      if (CVSS.vectorStringRegex_30.test(this.cvssVector)) {
        vector = CVSS.CVSSVersionIdentifier;
      } else {
        // Default to 3.1
        vector = CVSS31.CVSSVersionIdentifier;
      }
      for (const [metric, value] of Object.entries(metrics)) {
        vector += `/${metric}:${value}`
      }
      return vector;
    },
    /**
     * Parses the given CVSS vector string and populates the CVSS metrics object with correct values.
     *
     * @param {string} vector The CVSS 3.x vector string
     */
    populateCvssMetricsFromVector: function (vector) {
      var metrics = vector.substring(CVSS31.CVSSVersionIdentifier.length).split("/");
      for (const m of metrics) {
        if (m === "") {
          continue;
        }
        var metricAndScore = m.split(':');
        if (metricAndScore[0] in this.cvssMetrics) {
          this.cvssMetrics[metricAndScore[0]] = metricAndScore[1];
        }
      }
    }
  },
  mounted () {
    this.showPageFromFragment(this.current_route);
    window.onhashchange = () => {
      this.current_route = window.location.hash;
      this.showPageFromFragment(this.current_route);
    }
  }
});
