# Threat Hunting & Detection Engineering Course

## 1. MITRE ATT&CK Fundamentals - Develop and Update Malicious Activity Model

1-1. Introduction

* Threat Hunting
* Benefits of Threat Hunting
* Threat Hunting Overview (6 steps)
* Fundamentals Learning Objectives

1-2. Detection Approaches

* Key Terms: Precision and Recall

Detection | Malicious | Benign
| ------------- |:-------------:| :-----:|
Detected Results | True Positive | False Positive
Not Detected | False Negative | True Negative

* Traditional Detection Approaches
  - Signature-based
  - Allow-List
  - Anomaly-based
* Detection Dimension

1-3. TTP-Based Detection

* Characterizing Malicious IOCs (Indicators of Compromise) vs TTPs (tactics, techniques, and procedures (TTPs))
* Difficulty of Changing Malicious Observables
  - Hash Values (Trivial)
  - IP Addresses (Easy)
  - Domain Names (Simple)
  - Network, Host Artifacts (Annoying)
  - Tools (Challenging)
  - TTPs (Tough)

1-4. Prioritization

* Purpose Driven
* Purpose and Prioritizing
* Prioritizing Based on Technology
* Prioritizing Based on Behavior
* APT3 Persistence Example
* Summary
  - Relevant to the technologies you use
  - That could impact your business
  - Not currently well-defended in your environment
  - Detectable in your environment
  - Commonly used by Groups of interest

1-5. Methodology Review

* TTP Hunting Methodology Overview
* Implemented in Loops

## 2. Develop Hypotheses and Abstract Analytics

2.1 Developing Hypotheses

* What is a Hypothesis?
* Hypothesis Creation
* Hypothesis Example

2.2 Hypothesis Considerations

* Biases Present In Threat Intelligence = Visibility bias, Victim bias, Novelty bias
* Biases When Threat Hunting = Availability bias, Anchorring bias
* Dealing with Biases
* Choosing Techniques
* Technique Considerations
* Defining Behavior Scope

2.3 Finding Low-Variance Behaviors

* Variance Scale for Attack Indicators
* Invariant Behaviors
* Developing Behavior-based hypotheses
* Process Considerations
* Attack Behaviors in Perspective

2.4 Researching Low-Variance Behaviors

* Technique Research: Scheduled Task
* How can the technique be invoked by an adversary?
* Researching Scheduled Job/Task Invariant Behaviors
* Open-Source Research Resources

2.5 Investigating Low-Variance Behaviors

* Using procmon to investigate invariant behaviors
* Filtered procmon from task scheduler service
* Debugging to investigate invariant behaviors
* Low-variance behaviors
  - File creations within the task directory
  - Registry changes made for new tasks
  - Network connection over RPC (port 135)
  - DLLs a sub-process information source
* Low-Variance Behavior Activity Sequence

2.6 Refining Hypotheses

* Hypothesis Considerations
* Refining the Scheduled Tasks Hypothesis
* Distinguishing Malicious from Benign
* Initial Hypothesis
* Refined Hypothesis: Local Scheduling
* Refined Hypothesis: Remote Scheduling
* Refined Hypothesis: Scheduling as Specified User
* Refinement Considerations

2.7 Creating Abstract Analytics

2.8 Leveraging External Resources

## 3. Determine Data Requirements

3.1 Determining Data Requirements

3.2 Diving into Data Sources

3.3 Leveraging External Resources

## 4. Identify and Mitigate Data Collection Gaps

4.1 Identify & Mitigate Data Collection Gaps

4.2 Time, Terrain, & Behavior Considerations

4.3 Developing A Sensor Strategy

4.4 Using Alternative Data Sources & Analytics

4.5 Communicating with Network Managers

4.6 Validating Configuration

## 5. Implement and Test Analytics

5.1 Implementing Analytics

5.2 Validating Analytics 

5.3 Improving Performance, Precision, & Recall

5.4 Expanding Time, Terrain, & Behavior

5.5 Exploring the Three Dimensions

5.6 Updating Analytics Example

## 6. Hunt / Detect Malicious Activity and Investigate

6.1 Hunt & Investigation

6.2 Identifying Outliers

6.3 Evaluating Hits

6.4 Documenting

6.5 Gathering Additional Information - MAD20 Threat Hunting & Detection Engineering Course

