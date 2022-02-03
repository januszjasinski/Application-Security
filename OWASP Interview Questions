# OWASP Interview Questions

## What is OWASP?

 - OWASP stands for Open Web Application Security Project.  
 - It is an organization which supports secure software development.

## How to mitigate SQL Injection risks?

 - Prepared Statements with Parameterized Queries: Always ensure that your SQL interpreter can always differentiate between code and data.
 - Use of Stored Procedures: Stored Procedure is like a function in C where the database administrator calls it whenever he/she needs it. It is not completely mitigated SQL injection but definitely helps in reducing risks of SQL injection by avoiding dynamic SQL generation inside.
 - White List Input Validation: Always use white list input validation and allow only preapproved input by the developer. Never use a blacklist approach as it is less secure than a whitelist approach.
 - Escaping All User Supplied Input
 - Enforcing the Least Privilege

## How to mitigate the risk of Weak authentication and session management?

 - Compliant with all the authentication and session management requirements defined in OWASP’s Application Security Verification Standard (ASVS) areas V2 (Authentication) and V3 (Session Management).
 - Always use a simple interface for developers. 
 - Consider the ESAPI Authenticator and User APIs as good examples to emulate, use, or build upon.
 - Use standard practices to secure session id by cross-site scripting attack.
 - https://hdivsecurity.com/owasp-broken-authentication-and-session-management

## How to mitigate the risk of Sensitive Data Exposure?

 - Prepare a threat model to secure data both in transit and at rest from both types of the attacker( e.g., insider attack, external user)
 - Encrypt data to protect it from any cyber attack.
 - Never store sensitive data unnecessarily. 
 - Discard it as soon as possible. Data you don’t have can’t be stolen.
 - Disable autocomplete on forms collecting sensitive data and disable caching for pages that contain sensitive data.
 - Always implement and ensure strong standard algorithms and strong keys are used, and proper key management is in place. Consider using FIPS 140 validated cryptographic modules.
 - Ensure passwords are stored with an algorithm specifically designed for password protection, such as bcrypt, PBKDF2, or scrypt.

## How to Prevent Breaches Due to Failure to Restrict URL Access

Proper authentication and proper authorization

 - Implement Authentication and authorization policies based on the role instead of based on the user.
 - Policies are highly configurable in favor of standard practices.
 - Deny all access by default, and allow only those controls which the user needs.

## Mention what flaw arises from session tokens having poor randomness across a range of values?

 - Session hijacking

## Mention what happens when an application takes user inserted data and sends it to a web browser without proper validation and escaping?

 - Cross site scripting

## Can You Tell Us More about XXS

Code injection in the client-side that permits the injection of malicious scripts in a web browser by an attacker. It can easily compromise cookies, session tokens, and lots of sensitive information.

 - In reflected XXS, the malicious script comes from the current HTTPS request and is not stored in the database, unlike in the stored XXS. 
 - In the DOM XXS, fully known as the Document Object Model XXS, the threats are found in the client-side code and not the server code.

## Mention what threat can be avoided by having unique usernames produced with a high degree of entropy?

Authorization Bypass can be avoided by having unique usernames generated with a high degree of entropy.

## xplain what is OWASP WebGoat and WebScarab?

 - WebGoat: Its an educational tool for learning related to application security, a baseline to test security tools against known issues. It’s a J2EE web application organized in “Security Lessons” based on tomcat and JDK 1.5.
 - WebScarab: It’s a framework for analysing HTTP/HTTPS traffic. It does various functions like fragment analysis, observer the traffic between the server and browser, manual intercept, session ID analysis, identifying new URLs within each page viewed
owasp interview question

## List Top 10 OWASP Vulnerabilities

https://owasp.org/Top10/

## Explain what threat arises from not flagging HTTP cookies with tokens as secure?

Access Control Violation threat arises from not flagging HTTP cookies with tokens as secure.

## Name the attack technique that implement a user’s session credential or session ID to an explicit value?

Dictionary attack can force a user’s session credential or session ID to an explicit value

## Explain what does OWASP Application Security Verification Standard (ASVS) project includes?

OWASP application security verification standard project includes

 - Use as a metric: It provides application owners and application developers with a yardstick with which to analyze the degree of trust that can be placed in their web applications
 - Use as a guidance: It provides information to security control developers as to what to build into security controls in order to meet the application security requirements
 - Use during procurement: It provides a basis for specifying application security verification requirements in contracts

## List out the controls to test during the assessment?

 - Information gathering
 - Configuration and Deploy management testing
 - Identify Management testing
 - Authenticate Testing
 - Authorization Testing
 - Session Management Testing
 - Data Validation Testing
 - Error Handling
 - Cryptography
 - Business logic testing
 - Client side testing

## Explain what the passive mode is or phase I of testing security in OWASP?

The passive mode or phase I of security testing includes understanding the application’s logic and gathering information using appropriate tools.  At the end of this phase, the tester should understand all the gates or access points of the application.

## Mention what is the threat you are exposed to if you do not verify authorization of user for direct references to restricted resources?

You are exposed to threat for insecure direct object references, if you do not verify authorization of user for direct references to limited or restricted resources.

## Explain what is OWASP ESAPI?

OWASP ESAPI (Enterprise Security API) is an open source web application security control library that enables developers to build or write lower risk applications.

## Mention what is the basic design of OWASP ESAPI?

The basic design of OWASP ESAPI includes

 - A set of security control interfaces
 - For each security control there is a reference implementation
 - For each security control, there are option for the implementation for y

## Do You Know How to Mitigate the Risks Occasioned by Weak Authentication and Session Management?

 - An organization should use a simple interface for developers at all times. 
 - One should consider the ESAPI authenticated or the User APIS for use, emulation, or building. 
 - Secondly, it has been proven that using standard practices for securing session ID from cross-site scripting attacks works. 
 - Lastly, a developer should follow all the session management and authentication requirements detailed in this online community’s ASVS and V3, responsible for session management.


## Tell Us about the Intrusion Detection System Types

There are four main types of Intrusion Detection Systems. The network intrusion Detection System, abbreviated as NIDS, monitors and analyzes incoming traffic networks while a Host-based Intrusion Detection System or HIDS monitors operating system files. 

The other two types are subsets. We have the signature-based and anomaly-based intrusion Detection System types. The former monitors and identifies threats after analyzing given patterns, including network traffic byte sequences, while the latter uses a machine learning approach that detects and adapts to vague threats.

## What Can You Tell Us about SSL Sessions and SSL Connections?

SSL, which refers to a Secured Socket Layer connection, is the basis for communicating with peer to peer links. It has a connection that maintains the SSL session. The SSL session symbolizes the security contract, consisting of a key and algorithm agreement. It is worth noting that one SSL session can have several SSL Connections. I should mention that an SSL connection is basically a transient peer to peer communications link.

## Can You Differentiate Authentication From Authorization?

Authentication verifies the identity of a user, entity, or website. It ascertains that someone is whoever they claim to be. 

Authorization refers to the rules determining the powers granted to given parties. It can also be defined as the process of determining whether a client is permitted to access a given file or use a resource. 

Authentication is, therefore, all about verification, while authorization focuses more on permissions. Also, you will need to log in and key your password for authentication, whereas you must have the proper clearance for authorization.

## What Do You Understand by Security Testing?

 - Security testing is one of the most critical types of software testing. 
 - It must be done before an application is released to the general public. 
 - Identifies the vulnerabilities in software. 
 - Protects data from attacks and intruders. 
 - Ensures that any confidential information in an application is protected against leakage. 
 - Organization or developer must do it regularly to identify and solve different threats.

## Tell Us about the Different Methodologies in Security Testing

There are three primary methodologies in security testing: White box, black box, and grey box. 

 - White box testing is usually used to ascertain if the code implementation has followed the right design. It also validates security functionalities and shows some of the existing vulnerabilities. In this type of testing, the testers are furnished with all kinds of information. 
 - In black-box testing, the defenses, security controls, and application designs are tested with little or no existing knowledge on how the application works. 
 - Lastly, testers in grey box testing are given only partial information. They have to figure the rest by themselves.

## You Have Mentioned Vulnerability a Number of Times. Please Define What is it?

 - A weakness in a given application that an attacker can take advantage of and inflict harm to a client’s application. 
 - It can either be a design flaw or an implementation bug that makes a system susceptible to attacks and weak. 
 - These can be easily identified and corrected through rigorous security testing. Other known and proven means include fixes and occasional patches.

## Define Intrusion Detection

 - Intrusion Detection uses a system or set of systems that determine threats or possible attacks and find ways of dealing with them. 
 - Collects information from different sources and systems before analyzing it and coming up with means of stopping these attacks. 
 - Some of the essential things that intrusion detection must check are abnormal activities and possible attacks. 
 - It also audits the system data and analyzes those obtained from different sources..

## Define Penetration Testing

- Security testing that helps developers identify a system’s vulnerabilities. 
- Evaluates a system’s security through a set of manual and automated techniques. 
- Once one vulnerability has been identified, the tester will dwell on it to locate even more vulnerabilities.

## Cross Site Request Forgery (CSRF)

- Attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated
- https://owasp.org/www-community/attacks/csrf
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
