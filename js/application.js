Vue.component('question-answer', {
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

Vue.component('question', {
  props: ['question'],
  template: '#question-template'
});

Vue.component('examples', {
  props: ['examples'],
  template: '#examples-template'
});

Vue.component('score-card', {
  props: ['metric', 'score'],
  template: '#score-card-template',
  data () {
    return {
      severityHigh: false,
      severityMedium: false,
      severityLow: false,
      humanFriendlyScore: undefined
    }
  },
  methods: {
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
    scoreToHumanFriendly: function () {
      humanScores = {
        AV: {
          N: 'Network',
          A: 'Adjecent',
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
      }
      this.humanFriendlyScore = humanScores[this.metric][this.score];
    }
  },
  mounted() {
    this.determineSeverity();
    this.scoreToHumanFriendly();
  }
});

var ScoreModal = Vue.component('score-modal', {
  props: ['cvssMetrics'],
  template: '#score-modal-template',
  data () {
    return {
      cvssVector: undefined,
      cvssScore: 0.0,
      severity: undefined,
      severityCritical: false,
      severityHigh: false,
      severityMedium: false,
      severityLow: false
    }
  },
  mounted() {
    this.cvssVector = this.cvssMetricsToVector(this.cvssMetrics);
    var score = CVSS.calculateCVSSFromVector(this.cvssVector);
    this.cvssScore = score.baseMetricScore;
    this.severity = score.baseSeverity;
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
  methods: {
    cvssMetricsToVector: function (metrics) {
      var vector = `${CVSS.CVSSVersionIdentifier}`
      for (const [metric, value] of Object.entries(metrics)) {
        vector += `/${metric}:${value}`
      }
      return vector;
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
    current_question: undefined,
    questions: {
      attack_vector_1: {
        title: 'Attack Vector',
        question: 'Does the attacker exploit the vulnerable component via the network stack?',
        answers: [{
          answer: 'Yes',
          onSelect: () => {
            this.app.showQuestion('attack_vector_2');
          }
        }, {
          answer: 'No',
          onSelect: () => {
            this.app.showQuestion('attack_vector_3');
          }
        }]
      },
      attack_vector_2: {
        title: 'Attack Vector',
        question: 'Can the vulnerability be exploited from across a router (OSI layer 3 network)?',
        answers: [{
          answer: 'Yes',
          extra: 'Vulnerability is exploitable from across the internet.',
          onSelect: () => {
            this.app.cvssMetrics.AV = 'N';
            this.app.showQuestion('attack_complexity_1');
          }
        }, {
          answer: 'No',
          extra: 'Vulnerability is exploitable across a limited physical or logical network distance.',
          onSelect: () => {
            this.app.cvssMetrics.AV = 'A';
            this.app.showQuestion('attack_complexity_1');
          }
        }]
      },
      attack_vector_3: {
        title: 'Attack Vector',
        question: 'Does the attacker require physical access to the target?',
        answers: [{
          answer: 'Yes',
          extra: 'Attacker requires physical access to the vulnerable component.',
          onSelect: () => {
            this.app.cvssMetrics.AV = 'L'
            this.app.showQuestion('attack_complexity_1');
          }
        }, {
          answer: 'No',
          extra: 'Attack is committed through a local application vulnerability, or the attacker is able to log in locally.',
          onSelect: () => {
            this.app.cvssMetrics.AV = 'P';
            this.app.showQuestion('attack_complexity_1');
          }
        }]
      },
      attack_complexity_1: {
        title: 'Attack Complexity',
        question: 'Can the attacker exploit the vulnerability at will?',
        answers: [{
          answer: 'Yes',
          extra: 'Attacker can expoit the vulnerability at any time, always.',
          examples: [
            'IDOR using simple guessable ID',
            "Stored XSS on a page that's part of the user's normal workflow (main project page, issue or merge request page, etc.)"
          ],
          onSelect: () => {
            this.app.cvssMetrics.AC = 'L';
            this.app.showQuestion('privileges_required_1');
          }
        }, {
          answer: 'No',
          extra: "Successful attack depends on conditions beyond the attacker's control.",
          examples: [
            'Knowledge of a private project name is required to carry out the attack',
            'A certain setting has to have a non-default value to make the attack possible',
            "CSRF and reflected XSS because it's likely the victim will not click the attacker's link",
            "Stored XSS on an obscure page that the victim's unlikely to visit without clicking a link from the attacker (on a specific job's build log for example)"
          ],
          onSelect: () => {
            this.app.cvssMetrics.AC = 'H';
            this.app.showQuestion('privileges_required_1');
          }
        }]
      },
      privileges_required_1: {
        title: 'Privileges Required',
        question: 'Must the attacker be authorized to the exploitable component prior to attack?',
        answers: [{
          answer: 'Yes',
          onSelect: () => {
            this.app.showQuestion('privileges_required_2');
          }
        }, {
          answer: 'No',
          examples: [
            'Permission issues allowing an unauthenticated account to access confidential information through the API',
            "CSRF or reflected XSS issues, assuming a privileged account isn't required to craft the attack URL",
          ],
          onSelect: () => {
            this.app.cvssMetrics.PR = 'N';
            this.app.showQuestion('user_interaction_1');
          }
        }]
      },
      privileges_required_2: {
        title: 'Privileges Required',
        question: 'Are administrator privileges required?',
        answers: [{
          answer: 'Yes',
          extra: 'Administrator or system level access required. Side note: high privilege users using a bug to sabotage their own projects is out of scope of our bug bounty program.',
          onSelect: () => {
            this.app.cvssMetrics.PR = 'H';
            this.app.showQuestion('user_interaction_1');
          }
        }, {
          answer: 'No',
          extra: 'User level access required.',
          onSelect: () => {
            this.app.cvssMetrics.PR = 'L';
            this.app.showQuestion('user_interaction_1');
          }
        }]
      },
      user_interaction_1: {
        title: 'User Interaction',
        question: 'Does the attacker require some other user to perform an action?',
        answers: [{
          answer: 'Yes',
          extra: 'Successful attack requires user interaction.',
          examples: [
            'All vulnerabilities that need a victim to do any stort of action even if the action is only to log on GitLab, this includes all XSS and CSRF vulnerabilities'
          ],
          onSelect: () => {
            this.app.cvssMetrics.UI = 'R';
            this.app.showQuestion('scope_1');
          }
        }, {
          answer: 'No',
          extra: 'Attack can be accomplished without any user interaction.',
          examples: [
            'Any attack that would work even if the victim never logs back in to GitLab'
          ],
          onSelect: () => {
            this.app.cvssMetrics.UI = 'N';
            this.app.showQuestion('scope_1');
          }
        }]
      },
      scope_1: {
        title: 'Scope',
        question: 'Can the attacker affect a component whose authority is different than the vulnerable component?',
        answers: [{
          answer: 'Yes',
          extra: 'Impact caused to systems beyond the exploitable component.',
          examples: [
            'XSS (vulnerable component is the website, impacted component is the browser)',
            'SSRF in GitLab that allows fetching GCP metadata'
          ],
          onSelect: () => {
            this.app.cvssMetrics.S = 'C';
            this.app.showQuestion('confidentiality_impact_1');
          }
        }, {
          answer: 'No',
          extra: 'Impact is localized to the exploitable component.',
          onSelect: () => {
            this.app.cvssMetrics.S = 'U';
            this.app.showQuestion('confidentiality_impact_1');
          }
        }]
      },
      confidentiality_impact_1: {
        title: 'Confidentiality Impact',
        question: 'Is there any impact to confidentiality?',
        answers: [{
          answer: 'Yes',
          onSelect: () => {
            this.app.showQuestion('confidentiality_impact_2');
          }
        }, {
          answer: 'No',
          extra: 'No information is disclosed.',
          onSelect: () => {
            this.app.cvssMetrics.C = "N";
            this.app.showQuestion('integrity_impact_1');
          }
        }]
      },
      confidentiality_impact_2: {
        title: 'Confidentiality Impact',
        question: 'Can attacker obtain all information from impacted component, or is the disclosed information critical?',
        answers: [{
          answer: 'Yes',
          extra: 'All information is disclosed to attacker, or only some critical information is disclosed.',
          onSelect: () => {
            this.app.cvssMetrics.C = 'H';
            this.app.showQuestion('integrity_impact_1');
          }
        }, {
          answer: 'No',
          extra: 'Some information can be obtained, and/or attacker does not have control over kind or degree.',
          examples: [
            'Access to private issue/MR titles but not their content',
            'Access to a small number of private issues/MR (one or a handful of projects, as opposed to being able to read any private issue on the instance)',
            "Access to private data that the attacker doesn't have access to anymore, but had access to in the past",
            'Access to private data of minor importance (issue due dates, private project name, etc.)'
          ],
          onSelect: () => {
            this.app.cvssMetrics.C = 'L';
            this.app.showQuestion('integrity_impact_1');
          }
        }]
      },
      integrity_impact_1: {
        title: 'Integrity Impact',
        question: 'Is there any impact to integrity?',
        answers: [{
          answer: 'Yes',
          onSelect: () => {
            this.app.showQuestion('integrity_impact_2');
          }
        }, {
          answer: 'No',
          extra: 'No integrity loss.',
          onSelect: () => {
            this.app.cvssMetrics.I = 'N';
            this.app.showQuestion('availability_impact_1');
          }
        }]
      },
      integrity_impact_2: {
        title: 'Integrity Impact',
        question: 'Can attacker modify all information of impacted component, or is the modified information critical?',
        answers: [{
          answer: 'Yes',
          extra: 'Attacker can modify any information at any time, or only some critical information can be modified.',
          examples: [
            "Attacker can add a malicious Runner to a project where they don't have the required permissions to do so",
            "Attacker can add a malicious OAuth application to the victim's trusted apps",
            'Attacker can modify all issues on the GitLab instance'
          ],
          onSelect: () => {
            this.app.cvssMetrics.I = 'H';
            this.app.showQuestion('availability_impact_1');
          }
        }, {
          answer: 'No',
          extra: 'Some information can be altered, and/or attacker does not have control over kind or degree.',
          onSelect: () => {
            this.app.cvssMetrics.I = 'L';
            this.app.showQuestion('availability_impact_1');
          }
        }]
      },
      availability_impact_1: {
        title: 'Availability Impact',
        question: 'Is there any impact to the availability of a resource?',
        answers: [{
          answer: 'Yes',
          onSelect: () => {
            this.app.showQuestion('availability_impact_2');
          }
        }, {
          answer: 'No',
          extra: 'No Availability impact.',
          onSelect: () => {
            this.app.cvssMetrics.A = 'N';
            this.app.showScore();
          }
        }]
      },
      availability_impact_2: {
        title: 'Availability Impact',
        question: 'Can attacker completely deny access to affected component, or is the resource critical?',
        answers: [{
          answer: 'Yes',
          extra: 'Resource is completely unavailable, or select resource is critical to the component',
          examples: [
            'The attacker can delete projects or groups',
            'Runners all stop picking up pipelines',
            'GitLab instance taken down'
          ],
          onSelect: () => {
            this.app.cvssMetrics.A = 'H';
            this.app.showScore();
          }
        }, {
          answer: 'No',
          extra: 'Reduced performance or interruption of resource availability or response.',
          examples: [
            'A small amount of projects are inaccessible but become available when the attack stops',
            "A small amount of users can't use the instance"
          ],
          onSelect: () => {
            this.app.cvssMetrics.A = 'L';
            this.app.showScore();
          }
        }]
      }
    }
  },
  methods: {
    showQuestion: function (key) {
      this.current_question = this.questions[key];
    },
    showScore: function () {
      var modalInstance = new ScoreModal({
        propsData: { cvssMetrics: this.cvssMetrics }
      });
      modalInstance.$mount();
      this.$el.appendChild(modalInstance.$el);
      var modal = new bootstrap.Modal(modalInstance.$el);
      modalInstance.$el.addEventListener('hidden.bs.modal', (event) => {
        window.location.reload();
      });
      modal.show();
    }
  },
  created () {
    this.showQuestion('attack_vector_1');
  }
});