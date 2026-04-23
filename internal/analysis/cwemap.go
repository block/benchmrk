// Package analysis provides vulnerability matching and metrics computation.
package analysis

// CWECategories maps CWE IDs to vulnerability categories for matching.
// Generated from MITRE CWE v4.19.1 (https://cwe.mitre.org/data/xml/cwec_latest.xml.zip).
// Contains 944 entries across 67 categories.
var CWECategories = map[string]string{
	// SQL Injection
	"CWE-89":  "sql-injection", // Improper Neutralization of Special Elements used in an SQ...
	"CWE-564": "sql-injection", // SQL Injection: Hibernate
	"CWE-943": "sql-injection", // Improper Neutralization of Special Elements in Data Query...

	// Cross-Site Scripting (XSS)
	"CWE-79": "xss", // Improper Neutralization of Input During Web Page Generati...
	"CWE-80": "xss", // Improper Neutralization of Script-Related HTML Tags in a ...
	"CWE-81": "xss", // Improper Neutralization of Script in an Error Message Web...
	"CWE-82": "xss", // Improper Neutralization of Script in Attributes of IMG Ta...
	"CWE-83": "xss", // Improper Neutralization of Script in Attributes in a Web ...
	"CWE-84": "xss", // Improper Neutralization of Encoded URI Schemes in a Web Page
	"CWE-85": "xss", // Doubled Character XSS Manipulations
	"CWE-86": "xss", // Improper Neutralization of Invalid Characters in Identifi...
	"CWE-87": "xss", // Improper Neutralization of Alternate XSS Syntax

	// Command Injection
	"CWE-77":   "command-injection", // Improper Neutralization of Special Elements used in a Com...
	"CWE-78":   "command-injection", // Improper Neutralization of Special Elements used in an OS...
	"CWE-88":   "command-injection", // Improper Neutralization of Argument Delimiters in a Comma...
	"CWE-624":  "command-injection", // Executable Regular Expression Error
	"CWE-1427": "command-injection", // Improper Neutralization of Input Used for LLM Prompting

	// Code Injection
	"CWE-94": "code-injection", // Improper Control of Generation of Code ('Code Injection')
	"CWE-95": "code-injection", // Improper Neutralization of Directives in Dynamically Eval...
	"CWE-96": "code-injection", // Improper Neutralization of Directives in Statically Saved...
	"CWE-97": "code-injection", // Improper Neutralization of Server-Side Includes (SSI) Wit...

	// Injection (General)
	"CWE-74":   "injection", // Improper Neutralization of Special Elements in Output Use...
	"CWE-75":   "injection", // Failure to Sanitize Special Elements into a Different Pla...
	"CWE-76":   "injection", // Improper Neutralization of Equivalent Special Elements
	"CWE-1236": "injection", // Improper Neutralization of Formula Elements in a CSV File

	// Expression Language Injection
	"CWE-917": "expression-injection", // Improper Neutralization of Special Elements used in an Ex...

	// Template Injection
	"CWE-1336": "template-injection", // Improper Neutralization of Special Elements Used in a Tem...

	// XML Injection
	"CWE-91": "xml-injection", // XML Injection (aka Blind XPath Injection)

	// CRLF Injection
	"CWE-93": "crlf-injection", // Improper Neutralization of CRLF Sequences ('CRLF Injection')

	// HTTP Response Splitting
	"CWE-113": "http-response-splitting", // Improper Neutralization of CRLF Sequences in HTTP Headers...

	// Format String
	"CWE-134": "format-string", // Use of Externally-Controlled Format String

	// Resource Injection
	"CWE-99":  "resource-injection", // Improper Control of Resource Identifiers ('Resource Injec...
	"CWE-102": "resource-injection", // Struts: Duplicate Validation Forms
	"CWE-462": "resource-injection", // Duplicate Key in Associative List (Alist)
	"CWE-621": "resource-injection", // Variable Extraction Error
	"CWE-627": "resource-injection", // Dynamic Variable Evaluation
	"CWE-641": "resource-injection", // Improper Restriction of Names for Files and Other Resources
	"CWE-694": "resource-injection", // Use of Multiple Resources with Duplicate Identifier
	"CWE-914": "resource-injection", // Improper Control of Dynamically-Identified Variables

	// LDAP Injection
	"CWE-90": "ldap-injection", // Improper Neutralization of Special Elements used in an LD...

	// XPath Injection
	"CWE-643": "xpath-injection", // Improper Neutralization of Data within XPath Expressions ...

	// XQuery Injection
	"CWE-652": "xquery-injection", // Improper Neutralization of Data within XQuery Expressions...

	// Path Traversal
	"CWE-22":  "path-traversal", // Improper Limitation of a Pathname to a Restricted Directo...
	"CWE-23":  "path-traversal", // Relative Path Traversal
	"CWE-24":  "path-traversal", // Path Traversal: '../filedir'
	"CWE-25":  "path-traversal", // Path Traversal: '/../filedir'
	"CWE-26":  "path-traversal", // Path Traversal: '/dir/../filename'
	"CWE-27":  "path-traversal", // Path Traversal: 'dir/../../filename'
	"CWE-28":  "path-traversal", // Path Traversal: '..\filedir'
	"CWE-29":  "path-traversal", // Path Traversal: '\..\filename'
	"CWE-30":  "path-traversal", // Path Traversal: '\dir\..\filename'
	"CWE-31":  "path-traversal", // Path Traversal: 'dir\..\..\filename'
	"CWE-32":  "path-traversal", // Path Traversal: '...' (Triple Dot)
	"CWE-33":  "path-traversal", // Path Traversal: '....' (Multiple Dot)
	"CWE-34":  "path-traversal", // Path Traversal: '....//'
	"CWE-35":  "path-traversal", // Path Traversal: '.../...//'
	"CWE-36":  "path-traversal", // Absolute Path Traversal
	"CWE-37":  "path-traversal", // Path Traversal: '/absolute/pathname/here'
	"CWE-38":  "path-traversal", // Path Traversal: '\absolute\pathname\here'
	"CWE-39":  "path-traversal", // Path Traversal: 'C:dirname'
	"CWE-40":  "path-traversal", // Path Traversal: '\\UNC\share\name\' (Windows UNC Share)
	"CWE-73":  "path-traversal", // External Control of File Name or Path
	"CWE-114": "path-traversal", // Process Control

	// Unrestricted File Upload
	"CWE-434": "unrestricted-upload", // Unrestricted Upload of File with Dangerous Type

	// XML External Entity (XXE)
	"CWE-611": "xxe", // Improper Restriction of XML External Entity Reference
	"CWE-776": "xxe", // Improper Restriction of Recursive Entity References in DT...

	// Server-Side Request Forgery (SSRF)
	"CWE-918": "ssrf", // Server-Side Request Forgery (SSRF)

	// Open Redirect
	"CWE-601": "open-redirect", // URL Redirection to Untrusted Site ('Open Redirect')

	// Cross-Site Request Forgery (CSRF)
	"CWE-352": "csrf", // Cross-Site Request Forgery (CSRF)

	// Request Smuggling
	"CWE-441":  "request-smuggling", // Unintended Proxy or Intermediary ('Confused Deputy')
	"CWE-1021": "request-smuggling", // Improper Restriction of Rendered UI Layers or Frames

	// Deserialization
	"CWE-502": "deserialization", // Deserialization of Untrusted Data

	// Authentication
	"CWE-13":   "authentication", // ASP.NET Misconfiguration: Password in Configuration File
	"CWE-41":   "authentication", // Improper Resolution of Path Equivalence
	"CWE-42":   "authentication", // Path Equivalence: 'filename.' (Trailing Dot)
	"CWE-43":   "authentication", // Path Equivalence: 'filename....' (Multiple Trailing Dot)
	"CWE-44":   "authentication", // Path Equivalence: 'file.name' (Internal Dot)
	"CWE-45":   "authentication", // Path Equivalence: 'file...name' (Multiple Internal Dot)
	"CWE-46":   "authentication", // Path Equivalence: 'filename ' (Trailing Space)
	"CWE-47":   "authentication", // Path Equivalence: ' filename' (Leading Space)
	"CWE-48":   "authentication", // Path Equivalence: 'file name' (Internal Whitespace)
	"CWE-49":   "authentication", // Path Equivalence: 'filename/' (Trailing Slash)
	"CWE-50":   "authentication", // Path Equivalence: '//multiple/leading/slash'
	"CWE-51":   "authentication", // Path Equivalence: '/multiple//internal/slash'
	"CWE-52":   "authentication", // Path Equivalence: '/multiple/trailing/slash//'
	"CWE-53":   "authentication", // Path Equivalence: '\multiple\\internal\backslash'
	"CWE-54":   "authentication", // Path Equivalence: 'filedir\' (Trailing Backslash)
	"CWE-55":   "authentication", // Path Equivalence: '/./' (Single Dot Directory)
	"CWE-56":   "authentication", // Path Equivalence: 'filedir*' (Wildcard)
	"CWE-57":   "authentication", // Path Equivalence: 'fakedir/../realdir/filename'
	"CWE-58":   "authentication", // Path Equivalence: Windows 8.3 Filename
	"CWE-256":  "authentication", // Plaintext Storage of a Password
	"CWE-257":  "authentication", // Storing Passwords in a Recoverable Format
	"CWE-258":  "authentication", // Empty Password in Configuration File
	"CWE-260":  "authentication", // Password in Configuration File
	"CWE-261":  "authentication", // Weak Encoding for Password
	"CWE-262":  "authentication", // Not Using Password Aging
	"CWE-263":  "authentication", // Password Aging with Long Expiration
	"CWE-287":  "authentication", // Improper Authentication
	"CWE-288":  "authentication", // Authentication Bypass Using an Alternate Path or Channel
	"CWE-289":  "authentication", // Authentication Bypass by Alternate Name
	"CWE-290":  "authentication", // Authentication Bypass by Spoofing
	"CWE-291":  "authentication", // Reliance on IP Address for Authentication
	"CWE-293":  "authentication", // Using Referer Field for Authentication
	"CWE-294":  "authentication", // Authentication Bypass by Capture-replay
	"CWE-295":  "authentication", // Improper Certificate Validation
	"CWE-296":  "authentication", // Improper Following of a Certificate's Chain of Trust
	"CWE-297":  "authentication", // Improper Validation of Certificate with Host Mismatch
	"CWE-298":  "authentication", // Improper Validation of Certificate Expiration
	"CWE-299":  "authentication", // Improper Check for Certificate Revocation
	"CWE-301":  "authentication", // Reflection Attack in an Authentication Protocol
	"CWE-302":  "authentication", // Authentication Bypass by Assumed-Immutable Data
	"CWE-303":  "authentication", // Incorrect Implementation of Authentication Algorithm
	"CWE-304":  "authentication", // Missing Critical Step in Authentication
	"CWE-305":  "authentication", // Authentication Bypass by Primary Weakness
	"CWE-306":  "authentication", // Missing Authentication for Critical Function
	"CWE-307":  "authentication", // Improper Restriction of Excessive Authentication Attempts
	"CWE-308":  "authentication", // Use of Single-factor Authentication
	"CWE-309":  "authentication", // Use of Password System for Primary Authentication
	"CWE-322":  "authentication", // Key Exchange without Entity Authentication
	"CWE-350":  "authentication", // Reliance on Reverse DNS Resolution for a Security-Critica...
	"CWE-370":  "authentication", // Missing Check for Certificate Revocation after Initial Check
	"CWE-384":  "authentication", // Session Fixation
	"CWE-425":  "authentication", // Direct Request ('Forced Browsing')
	"CWE-521":  "authentication", // Weak Password Requirements
	"CWE-523":  "authentication", // Unprotected Transport of Credentials
	"CWE-549":  "authentication", // Missing Password Field Masking
	"CWE-555":  "authentication", // J2EE Misconfiguration: Plaintext Password in Configuratio...
	"CWE-593":  "authentication", // Authentication Bypass: OpenSSL CTX Object Modified after ...
	"CWE-599":  "authentication", // Missing Validation of OpenSSL Certificate
	"CWE-603":  "authentication", // Use of Client-Side Authentication
	"CWE-620":  "authentication", // Unverified Password Change
	"CWE-640":  "authentication", // Weak Password Recovery Mechanism for Forgotten Password
	"CWE-645":  "authentication", // Overly Restrictive Account Lockout Mechanism
	"CWE-804":  "authentication", // Guessable CAPTCHA
	"CWE-836":  "authentication", // Use of Password Hash Instead of Password for Authentication
	"CWE-1299": "authentication", // Missing Protection Mechanism for Alternate Hardware Inter...
	"CWE-1390": "authentication", // Weak Authentication
	"CWE-1391": "authentication", // Use of Weak Credentials
	"CWE-1392": "authentication", // Use of Default Credentials
	"CWE-1393": "authentication", // Use of Default Password
	"CWE-1394": "authentication", // Use of Default Cryptographic Key

	// Authorization
	"CWE-202":  "authorization", // Exposure of Sensitive Information Through Data Queries
	"CWE-219":  "authorization", // Storage of File with Sensitive Data Under Web Root
	"CWE-220":  "authorization", // Storage of File With Sensitive Data Under FTP Root
	"CWE-276":  "authorization", // Incorrect Default Permissions
	"CWE-277":  "authorization", // Insecure Inherited Permissions
	"CWE-278":  "authorization", // Insecure Preserved Inherited Permissions
	"CWE-279":  "authorization", // Incorrect Execution-Assigned Permissions
	"CWE-281":  "authorization", // Improper Preservation of Permissions
	"CWE-285":  "authorization", // Improper Authorization
	"CWE-424":  "authorization", // Improper Protection of Alternate Path
	"CWE-433":  "authorization", // Unparsed Raw Web Content Delivery
	"CWE-527":  "authorization", // Exposure of Version-Control Repository to an Unauthorized...
	"CWE-528":  "authorization", // Exposure of Core Dump File to an Unauthorized Control Sphere
	"CWE-529":  "authorization", // Exposure of Access Control List Files to an Unauthorized ...
	"CWE-530":  "authorization", // Exposure of Backup File to an Unauthorized Control Sphere
	"CWE-539":  "authorization", // Use of Persistent Cookies Containing Sensitive Information
	"CWE-551":  "authorization", // Incorrect Behavior Order: Authorization Before Parsing an...
	"CWE-552":  "authorization", // Files or Directories Accessible to External Parties
	"CWE-553":  "authorization", // Command Shell in Externally Accessible Directory
	"CWE-612":  "authorization", // Improper Authorization of Index Containing Sensitive Info...
	"CWE-638":  "authorization", // Not Using Complete Mediation
	"CWE-647":  "authorization", // Use of Non-Canonical URL Paths for Authorization Decisions
	"CWE-732":  "authorization", // Incorrect Permission Assignment for Critical Resource
	"CWE-766":  "authorization", // Critical Data Element Declared Public
	"CWE-862":  "authorization", // Missing Authorization
	"CWE-863":  "authorization", // Incorrect Authorization
	"CWE-926":  "authorization", // Improper Export of Android Application Components
	"CWE-927":  "authorization", // Use of Implicit Intent for Sensitive Communication
	"CWE-939":  "authorization", // Improper Authorization in Handler for Custom URL Scheme
	"CWE-1004": "authorization", // Sensitive Cookie Without 'HttpOnly' Flag
	"CWE-1230": "authorization", // Exposure of Sensitive Information Through Metadata
	"CWE-1244": "authorization", // Internal Asset Exposed to Unsafe Debug Access Level or State
	"CWE-1256": "authorization", // Improper Restriction of Software Interfaces to Hardware F...
	"CWE-1297": "authorization", // Unprotected Confidential Information on Device is Accessi...
	"CWE-1314": "authorization", // Missing Write Protection for Parametric Data Values
	"CWE-1328": "authorization", // Security Version Number Mutable to Older Versions

	// Broken Access Control (IDOR)
	"CWE-566": "broken-access-control", // Authorization Bypass Through User-Controlled SQL Primary Key
	"CWE-639": "broken-access-control", // Authorization Bypass Through User-Controlled Key

	// Access Control (General)
	"CWE-282":  "access-control", // Improper Ownership Management
	"CWE-283":  "access-control", // Unverified Ownership
	"CWE-284":  "access-control", // Improper Access Control
	"CWE-286":  "access-control", // Incorrect User Management
	"CWE-300":  "access-control", // Channel Accessible by Non-Endpoint
	"CWE-419":  "access-control", // Unprotected Primary Channel
	"CWE-420":  "access-control", // Unprotected Alternate Channel
	"CWE-421":  "access-control", // Race Condition During Access to Alternate Channel
	"CWE-422":  "access-control", // Unprotected Windows Messaging Channel ('Shatter')
	"CWE-618":  "access-control", // Exposed Unsafe ActiveX Method
	"CWE-708":  "access-control", // Incorrect Ownership Assignment
	"CWE-749":  "access-control", // Exposed Dangerous Method or Function
	"CWE-782":  "access-control", // Exposed IOCTL with Insufficient Access Control
	"CWE-842":  "access-control", // Placement of User into Incorrect Group
	"CWE-923":  "access-control", // Improper Restriction of Communication Channel to Intended...
	"CWE-941":  "access-control", // Incorrectly Specified Destination in a Communication Channel
	"CWE-1191": "access-control", // On-Chip Debug and Test Interface With Improper Access Con...
	"CWE-1220": "access-control", // Insufficient Granularity of Access Control
	"CWE-1222": "access-control", // Insufficient Granularity of Address Regions Protected by ...
	"CWE-1224": "access-control", // Improper Restriction of Write-Once Bit Fields
	"CWE-1231": "access-control", // Improper Prevention of Lock Bit Modification
	"CWE-1233": "access-control", // Security-Sensitive Hardware Controls with Missing Lock Bi...
	"CWE-1243": "access-control", // Sensitive Non-Volatile Information Not Protected During D...
	"CWE-1252": "access-control", // CPU Hardware Not Configured to Support Exclusivity of Wri...
	"CWE-1257": "access-control", // Improper Access Control Applied to Mirrored or Aliased Me...
	"CWE-1259": "access-control", // Improper Restriction of Security Token Assignment
	"CWE-1260": "access-control", // Improper Handling of Overlap Between Protected Memory Ranges
	"CWE-1262": "access-control", // Improper Access Control for Register Interface
	"CWE-1263": "access-control", // Improper Physical Access Control
	"CWE-1267": "access-control", // Policy Uses Obsolete Encoding
	"CWE-1270": "access-control", // Generation of Incorrect Security Tokens
	"CWE-1274": "access-control", // Improper Access Control for Volatile Memory Containing Bo...
	"CWE-1275": "access-control", // Sensitive Cookie with Improper SameSite Attribute
	"CWE-1276": "access-control", // Hardware Child Block Incorrectly Connected to Parent System
	"CWE-1280": "access-control", // Access Control Check Implemented After Asset is Accessed
	"CWE-1283": "access-control", // Mutable Attestation or Measurement Reporting Data
	"CWE-1290": "access-control", // Incorrect Decoding of Security Identifiers
	"CWE-1292": "access-control", // Incorrect Conversion of Security Identifiers
	"CWE-1294": "access-control", // Insecure Security Identifier Mechanism
	"CWE-1296": "access-control", // Incorrect Chaining or Granularity of Debug Components
	"CWE-1302": "access-control", // Missing Source Identifier in Entity Transactions on a Sys...
	"CWE-1304": "access-control", // Improperly Preserved Integrity of Hardware Configuration ...
	"CWE-1311": "access-control", // Improper Translation of Security Attributes by Fabric Bridge
	"CWE-1312": "access-control", // Missing Protection for Mirrored Regions in On-Chip Fabric...
	"CWE-1313": "access-control", // Hardware Allows Activation of Test or Debug Logic at Runtime
	"CWE-1315": "access-control", // Improper Setting of Bus Controlling Capability in Fabric ...
	"CWE-1316": "access-control", // Fabric-Address Map Allows Programming of Unwarranted Over...
	"CWE-1317": "access-control", // Improper Access Control in Fabric Bridge
	"CWE-1320": "access-control", // Improper Protection for Outbound Error Messages and Alert...
	"CWE-1323": "access-control", // Improper Management of Sensitive Trace Data
	"CWE-1334": "access-control", // Unauthorized Error Injection Can Degrade Hardware Redundancy

	// CORS Misconfiguration
	"CWE-942": "cors-misconfiguration", // Permissive Cross-domain Security Policy with Untrusted Do...

	// Origin Validation
	"CWE-346":  "origin-validation", // Origin Validation Error
	"CWE-925":  "origin-validation", // Improper Verification of Intent by Broadcast Receiver
	"CWE-940":  "origin-validation", // Improper Verification of Source of a Communication Channel
	"CWE-1385": "origin-validation", // Missing Origin Validation in WebSockets

	// Privilege Management
	"CWE-9":    "privilege-management", // J2EE Misconfiguration: Weak Access Permissions for EJB Me...
	"CWE-250":  "privilege-management", // Execution with Unnecessary Privileges
	"CWE-266":  "privilege-management", // Incorrect Privilege Assignment
	"CWE-267":  "privilege-management", // Privilege Defined With Unsafe Actions
	"CWE-268":  "privilege-management", // Privilege Chaining
	"CWE-269":  "privilege-management", // Improper Privilege Management
	"CWE-270":  "privilege-management", // Privilege Context Switching Error
	"CWE-271":  "privilege-management", // Privilege Dropping / Lowering Errors
	"CWE-272":  "privilege-management", // Least Privilege Violation
	"CWE-273":  "privilege-management", // Improper Check for Dropped Privileges
	"CWE-274":  "privilege-management", // Improper Handling of Insufficient Privileges
	"CWE-520":  "privilege-management", // .NET Misconfiguration: Use of Impersonation
	"CWE-556":  "privilege-management", // ASP.NET Misconfiguration: Use of Identity Impersonation
	"CWE-623":  "privilege-management", // Unsafe ActiveX Control Marked Safe For Scripting
	"CWE-648":  "privilege-management", // Incorrect Use of Privileged APIs
	"CWE-1022": "privilege-management", // Use of Web Link to Untrusted Target with window.opener Ac...
	"CWE-1268": "privilege-management", // Policy Privileges are not Assigned Consistently Between C...

	// Hardcoded Credentials
	"CWE-259": "hardcoded-credentials", // Use of Hard-coded Password
	"CWE-321": "hardcoded-credentials", // Use of Hard-coded Cryptographic Key
	"CWE-798": "hardcoded-credentials", // Use of Hard-coded Credentials

	// Insufficiently Protected Credentials
	"CWE-522": "insufficiently-protected-credentials", // Insufficiently Protected Credentials

	// Weak Cryptography
	"CWE-6":    "weak-crypto", // J2EE Misconfiguration: Insufficient Session-ID Length
	"CWE-323":  "weak-crypto", // Reusing a Nonce, Key Pair in Encryption
	"CWE-325":  "weak-crypto", // Missing Cryptographic Step
	"CWE-326":  "weak-crypto", // Inadequate Encryption Strength
	"CWE-327":  "weak-crypto", // Use of a Broken or Risky Cryptographic Algorithm
	"CWE-328":  "weak-crypto", // Use of Weak Hash
	"CWE-329":  "weak-crypto", // Generation of Predictable IV with CBC Mode
	"CWE-330":  "weak-crypto", // Use of Insufficiently Random Values
	"CWE-331":  "weak-crypto", // Insufficient Entropy
	"CWE-332":  "weak-crypto", // Insufficient Entropy in PRNG
	"CWE-333":  "weak-crypto", // Improper Handling of Insufficient Entropy in TRNG
	"CWE-334":  "weak-crypto", // Small Space of Random Values
	"CWE-335":  "weak-crypto", // Incorrect Usage of Seeds in Pseudo-Random Number Generato...
	"CWE-336":  "weak-crypto", // Same Seed in Pseudo-Random Number Generator (PRNG)
	"CWE-337":  "weak-crypto", // Predictable Seed in Pseudo-Random Number Generator (PRNG)
	"CWE-338":  "weak-crypto", // Use of Cryptographically Weak Pseudo-Random Number Genera...
	"CWE-339":  "weak-crypto", // Small Seed Space in PRNG
	"CWE-340":  "weak-crypto", // Generation of Predictable Numbers or Identifiers
	"CWE-341":  "weak-crypto", // Predictable from Observable State
	"CWE-342":  "weak-crypto", // Predictable Exact Value from Previous Values
	"CWE-343":  "weak-crypto", // Predictable Value Range from Previous Values
	"CWE-344":  "weak-crypto", // Use of Invariant Value in Dynamically Changing Context
	"CWE-453":  "weak-crypto", // Insecure Default Variable Initialization
	"CWE-587":  "weak-crypto", // Assignment of a Fixed Address to a Pointer
	"CWE-759":  "weak-crypto", // Use of a One-Way Hash without a Salt
	"CWE-760":  "weak-crypto", // Use of a One-Way Hash with a Predictable Salt
	"CWE-780":  "weak-crypto", // Use of RSA Algorithm without OAEP
	"CWE-916":  "weak-crypto", // Use of Password Hash With Insufficient Computational Effort
	"CWE-1188": "weak-crypto", // Initialization of a Resource with an Insecure Default
	"CWE-1204": "weak-crypto", // Generation of Weak Initialization Vector (IV)
	"CWE-1240": "weak-crypto", // Use of a Cryptographic Primitive with a Risky Implementation
	"CWE-1241": "weak-crypto", // Use of Predictable Algorithm in Random Number Generator

	// Missing Encryption
	"CWE-5":    "missing-encryption", // J2EE Misconfiguration: Data Transmission Without Encryption
	"CWE-311":  "missing-encryption", // Missing Encryption of Sensitive Data
	"CWE-312":  "missing-encryption", // Cleartext Storage of Sensitive Information
	"CWE-313":  "missing-encryption", // Cleartext Storage in a File or on Disk
	"CWE-314":  "missing-encryption", // Cleartext Storage in the Registry
	"CWE-315":  "missing-encryption", // Cleartext Storage of Sensitive Information in a Cookie
	"CWE-316":  "missing-encryption", // Cleartext Storage of Sensitive Information in Memory
	"CWE-317":  "missing-encryption", // Cleartext Storage of Sensitive Information in GUI
	"CWE-318":  "missing-encryption", // Cleartext Storage of Sensitive Information in Executable
	"CWE-319":  "missing-encryption", // Cleartext Transmission of Sensitive Information
	"CWE-526":  "missing-encryption", // Cleartext Storage of Sensitive Information in an Environm...
	"CWE-614":  "missing-encryption", // Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
	"CWE-1428": "missing-encryption", // Reliance on HTTP instead of HTTPS

	// Information Disclosure
	"CWE-8":    "information-disclosure", // J2EE Misconfiguration: Entity Bean Declared Remote
	"CWE-15":   "information-disclosure", // External Control of System or Configuration Setting
	"CWE-200":  "information-disclosure", // Exposure of Sensitive Information to an Unauthorized Actor
	"CWE-201":  "information-disclosure", // Insertion of Sensitive Information Into Sent Data
	"CWE-203":  "information-disclosure", // Observable Discrepancy
	"CWE-204":  "information-disclosure", // Observable Response Discrepancy
	"CWE-205":  "information-disclosure", // Observable Behavioral Discrepancy
	"CWE-206":  "information-disclosure", // Observable Internal Behavioral Discrepancy
	"CWE-207":  "information-disclosure", // Observable Behavioral Discrepancy With Equivalent Products
	"CWE-208":  "information-disclosure", // Observable Timing Discrepancy
	"CWE-209":  "information-disclosure", // Generation of Error Message Containing Sensitive Information
	"CWE-210":  "information-disclosure", // Self-generated Error Message Containing Sensitive Informa...
	"CWE-211":  "information-disclosure", // Externally-Generated Error Message Containing Sensitive I...
	"CWE-213":  "information-disclosure", // Exposure of Sensitive Information Due to Incompatible Pol...
	"CWE-214":  "information-disclosure", // Invocation of Process Using Visible Sensitive Information
	"CWE-215":  "information-disclosure", // Insertion of Sensitive Information Into Debugging Code
	"CWE-359":  "information-disclosure", // Exposure of Private Personal Information to an Unauthoriz...
	"CWE-374":  "information-disclosure", // Passing Mutable Objects to an Untrusted Method
	"CWE-375":  "information-disclosure", // Returning a Mutable Object to an Untrusted Caller
	"CWE-377":  "information-disclosure", // Insecure Temporary File
	"CWE-378":  "information-disclosure", // Creation of Temporary File With Insecure Permissions
	"CWE-379":  "information-disclosure", // Creation of Temporary File in Directory with Insecure Per...
	"CWE-402":  "information-disclosure", // Transmission of Private Resources into a New Sphere ('Res...
	"CWE-403":  "information-disclosure", // Exposure of File Descriptor to Unintended Control Sphere ...
	"CWE-426":  "information-disclosure", // Untrusted Search Path
	"CWE-427":  "information-disclosure", // Uncontrolled Search Path Element
	"CWE-428":  "information-disclosure", // Unquoted Search Path or Element
	"CWE-472":  "information-disclosure", // External Control of Assumed-Immutable Web Parameter
	"CWE-488":  "information-disclosure", // Exposure of Data Element to Wrong Session
	"CWE-491":  "information-disclosure", // Public cloneable() Method Without Final ('Object Hijack')
	"CWE-492":  "information-disclosure", // Use of Inner Class Containing Sensitive Data
	"CWE-493":  "information-disclosure", // Critical Public Variable Without Final Modifier
	"CWE-497":  "information-disclosure", // Exposure of Sensitive System Information to an Unauthoriz...
	"CWE-498":  "information-disclosure", // Cloneable Class Containing Sensitive Information
	"CWE-499":  "information-disclosure", // Serializable Class Containing Sensitive Data
	"CWE-500":  "information-disclosure", // Public Static Field Not Marked Final
	"CWE-524":  "information-disclosure", // Use of Cache Containing Sensitive Information
	"CWE-525":  "information-disclosure", // Use of Web Browser Cache Containing Sensitive Information
	"CWE-531":  "information-disclosure", // Inclusion of Sensitive Information in Test Code
	"CWE-532":  "information-disclosure", // Insertion of Sensitive Information into Log File
	"CWE-535":  "information-disclosure", // Exposure of Information Through Shell Error Message
	"CWE-536":  "information-disclosure", // Servlet Runtime Error Message Containing Sensitive Inform...
	"CWE-537":  "information-disclosure", // Java Runtime Error Message Containing Sensitive Information
	"CWE-538":  "information-disclosure", // Insertion of Sensitive Information into Externally-Access...
	"CWE-540":  "information-disclosure", // Inclusion of Sensitive Information in Source Code
	"CWE-541":  "information-disclosure", // Inclusion of Sensitive Information in an Include File
	"CWE-548":  "information-disclosure", // Exposure of Information Through Directory Listing
	"CWE-550":  "information-disclosure", // Server-generated Error Message Containing Sensitive Infor...
	"CWE-565":  "information-disclosure", // Reliance on Cookies without Validation and Integrity Chec...
	"CWE-582":  "information-disclosure", // Array Declared Public, Final, and Static
	"CWE-583":  "information-disclosure", // finalize() Method Declared Public
	"CWE-598":  "information-disclosure", // Use of GET Request Method With Sensitive Query Strings
	"CWE-608":  "information-disclosure", // Struts: Non-private Field in ActionForm Class
	"CWE-615":  "information-disclosure", // Inclusion of Sensitive Information in Source Code Comments
	"CWE-619":  "information-disclosure", // Dangling Database Cursor ('Cursor Injection')
	"CWE-642":  "information-disclosure", // External Control of Critical State Data
	"CWE-651":  "information-disclosure", // Exposure of WSDL File Containing Sensitive Information
	"CWE-668":  "information-disclosure", // Exposure of Resource to Wrong Sphere
	"CWE-767":  "information-disclosure", // Access to Critical Private Variable via Public Method
	"CWE-784":  "information-disclosure", // Reliance on Cookies without Validation and Integrity Chec...
	"CWE-1189": "information-disclosure", // Improper Isolation of Shared Resources on System-on-a-Chi...
	"CWE-1254": "information-disclosure", // Incorrect Comparison Logic Granularity
	"CWE-1255": "information-disclosure", // Comparison Logic is Vulnerable to Power Side-Channel Attacks
	"CWE-1273": "information-disclosure", // Device Unlock Credential Sharing
	"CWE-1282": "information-disclosure", // Assumed-Immutable Data is Stored in Writable Memory
	"CWE-1295": "information-disclosure", // Debug Messages Revealing Unnecessary Information
	"CWE-1300": "information-disclosure", // Improper Protection of Physical Side Channels
	"CWE-1303": "information-disclosure", // Non-Transparent Sharing of Microarchitectural Resources
	"CWE-1327": "information-disclosure", // Binding to an Unrestricted IP Address
	"CWE-1331": "information-disclosure", // Improper Isolation of Shared Resources in Network On Chip...
	"CWE-1431": "information-disclosure", // Driving Intermediate Cryptographic State/Results to Hardw...

	// Data Authenticity
	"CWE-345":  "data-authenticity", // Insufficient Verification of Data Authenticity
	"CWE-347":  "data-authenticity", // Improper Verification of Cryptographic Signature
	"CWE-348":  "data-authenticity", // Use of Less Trusted Source
	"CWE-349":  "data-authenticity", // Acceptance of Extraneous Untrusted Data With Trusted Data
	"CWE-351":  "data-authenticity", // Insufficient Type Distinction
	"CWE-353":  "data-authenticity", // Missing Support for Integrity Check
	"CWE-354":  "data-authenticity", // Improper Validation of Integrity Check Value
	"CWE-360":  "data-authenticity", // Trust of System Event Data
	"CWE-494":  "data-authenticity", // Download of Code Without Integrity Check
	"CWE-616":  "data-authenticity", // Incomplete Identification of Uploaded File Variables (PHP)
	"CWE-646":  "data-authenticity", // Reliance on File Name or Extension of Externally-Supplied...
	"CWE-649":  "data-authenticity", // Reliance on Obfuscation or Encryption of Security-Relevan...
	"CWE-924":  "data-authenticity", // Improper Enforcement of Message Integrity During Transmis...
	"CWE-1293": "data-authenticity", // Missing Source Correlation of Multiple Independent Data

	// Input Validation
	"CWE-20":   "input-validation", // Improper Input Validation
	"CWE-103":  "input-validation", // Struts: Incomplete validate() Method Definition
	"CWE-104":  "input-validation", // Struts: Form Bean Does Not Extend Validation Class
	"CWE-105":  "input-validation", // Struts: Form Field Without Validator
	"CWE-106":  "input-validation", // Struts: Plug-in Framework not in Use
	"CWE-107":  "input-validation", // Struts: Unused Validation Form
	"CWE-108":  "input-validation", // Struts: Unvalidated Action Form
	"CWE-109":  "input-validation", // Struts: Validator Turned Off
	"CWE-110":  "input-validation", // Struts: Validator Without Form Field
	"CWE-111":  "input-validation", // Direct Use of Unsafe JNI
	"CWE-112":  "input-validation", // Missing XML Validation
	"CWE-123":  "input-validation", // Write-what-where Condition
	"CWE-124":  "input-validation", // Buffer Underwrite ('Buffer Underflow')
	"CWE-125":  "input-validation", // Out-of-bounds Read
	"CWE-126":  "input-validation", // Buffer Over-read
	"CWE-127":  "input-validation", // Buffer Under-read
	"CWE-129":  "input-validation", // Improper Validation of Array Index
	"CWE-130":  "input-validation", // Improper Handling of Length Parameter Inconsistency
	"CWE-138":  "input-validation", // Improper Neutralization of Special Elements
	"CWE-140":  "input-validation", // Improper Neutralization of Delimiters
	"CWE-141":  "input-validation", // Improper Neutralization of Parameter/Argument Delimiters
	"CWE-142":  "input-validation", // Improper Neutralization of Value Delimiters
	"CWE-143":  "input-validation", // Improper Neutralization of Record Delimiters
	"CWE-144":  "input-validation", // Improper Neutralization of Line Delimiters
	"CWE-145":  "input-validation", // Improper Neutralization of Section Delimiters
	"CWE-146":  "input-validation", // Improper Neutralization of Expression/Command Delimiters
	"CWE-147":  "input-validation", // Improper Neutralization of Input Terminators
	"CWE-148":  "input-validation", // Improper Neutralization of Input Leaders
	"CWE-149":  "input-validation", // Improper Neutralization of Quoting Syntax
	"CWE-150":  "input-validation", // Improper Neutralization of Escape, Meta, or Control Seque...
	"CWE-151":  "input-validation", // Improper Neutralization of Comment Delimiters
	"CWE-152":  "input-validation", // Improper Neutralization of Macro Symbols
	"CWE-153":  "input-validation", // Improper Neutralization of Substitution Characters
	"CWE-154":  "input-validation", // Improper Neutralization of Variable Name Delimiters
	"CWE-155":  "input-validation", // Improper Neutralization of Wildcards or Matching Symbols
	"CWE-156":  "input-validation", // Improper Neutralization of Whitespace
	"CWE-157":  "input-validation", // Failure to Sanitize Paired Delimiters
	"CWE-158":  "input-validation", // Improper Neutralization of Null Byte or NUL Character
	"CWE-159":  "input-validation", // Improper Handling of Invalid Use of Special Elements
	"CWE-160":  "input-validation", // Improper Neutralization of Leading Special Elements
	"CWE-161":  "input-validation", // Improper Neutralization of Multiple Leading Special Elements
	"CWE-162":  "input-validation", // Improper Neutralization of Trailing Special Elements
	"CWE-163":  "input-validation", // Improper Neutralization of Multiple Trailing Special Elem...
	"CWE-164":  "input-validation", // Improper Neutralization of Internal Special Elements
	"CWE-165":  "input-validation", // Improper Neutralization of Multiple Internal Special Elem...
	"CWE-166":  "input-validation", // Improper Handling of Missing Special Element
	"CWE-167":  "input-validation", // Improper Handling of Additional Special Element
	"CWE-168":  "input-validation", // Improper Handling of Inconsistent Special Elements
	"CWE-170":  "input-validation", // Improper Null Termination
	"CWE-179":  "input-validation", // Incorrect Behavior Order: Early Validation
	"CWE-180":  "input-validation", // Incorrect Behavior Order: Validate Before Canonicalize
	"CWE-181":  "input-validation", // Incorrect Behavior Order: Validate Before Filter
	"CWE-183":  "input-validation", // Permissive List of Allowed Inputs
	"CWE-415":  "input-validation", // Double Free
	"CWE-464":  "input-validation", // Addition of Data Structure Sentinel
	"CWE-466":  "input-validation", // Return of Pointer Value Outside of Expected Range
	"CWE-470":  "input-validation", // Use of Externally-Controlled Input to Select Classes or C...
	"CWE-554":  "input-validation", // ASP.NET Misconfiguration: Not Using Input Validation Fram...
	"CWE-606":  "input-validation", // Unchecked Input for Loop Condition
	"CWE-622":  "input-validation", // Improper Validation of Function Hook Arguments
	"CWE-626":  "input-validation", // Null Byte Interaction Error (Poison Null Byte)
	"CWE-680":  "input-validation", // Integer Overflow to Buffer Overflow
	"CWE-781":  "input-validation", // Improper Address Validation in IOCTL with METHOD_NEITHER ...
	"CWE-785":  "input-validation", // Use of Path Manipulation Function without Maximum-sized B...
	"CWE-786":  "input-validation", // Access of Memory Location Before Start of Buffer
	"CWE-788":  "input-validation", // Access of Memory Location After End of Buffer
	"CWE-790":  "input-validation", // Improper Filtering of Special Elements
	"CWE-791":  "input-validation", // Incomplete Filtering of Special Elements
	"CWE-792":  "input-validation", // Incomplete Filtering of One or More Instances of Special ...
	"CWE-793":  "input-validation", // Only Filtering One Instance of a Special Element
	"CWE-794":  "input-validation", // Incomplete Filtering of Multiple Instances of Special Ele...
	"CWE-795":  "input-validation", // Only Filtering Special Elements at a Specified Location
	"CWE-796":  "input-validation", // Only Filtering Special Elements Relative to a Marker
	"CWE-797":  "input-validation", // Only Filtering Special Elements at an Absolute Position
	"CWE-805":  "input-validation", // Buffer Access with Incorrect Length Value
	"CWE-806":  "input-validation", // Buffer Access Using Size of Source Buffer
	"CWE-822":  "input-validation", // Untrusted Pointer Dereference
	"CWE-823":  "input-validation", // Use of Out-of-range Pointer Offset
	"CWE-824":  "input-validation", // Access of Uninitialized Pointer
	"CWE-825":  "input-validation", // Expired Pointer Dereference
	"CWE-1173": "input-validation", // Improper Use of Validation Framework
	"CWE-1174": "input-validation", // ASP.NET Misconfiguration: Improper Model Validation
	"CWE-1284": "input-validation", // Improper Validation of Specified Quantity in Input
	"CWE-1285": "input-validation", // Improper Validation of Specified Index, Position, or Offs...
	"CWE-1286": "input-validation", // Improper Validation of Syntactic Correctness of Input
	"CWE-1287": "input-validation", // Improper Validation of Specified Type of Input
	"CWE-1288": "input-validation", // Improper Validation of Consistency within Input
	"CWE-1289": "input-validation", // Improper Validation of Unsafe Equivalence in Input

	// Mass Assignment
	"CWE-915":  "mass-assignment", // Improperly Controlled Modification of Dynamically-Determi...
	"CWE-1321": "mass-assignment", // Improperly Controlled Modification of Object Prototype At...

	// Race Condition
	"CWE-362":  "race-condition", // Concurrent Execution using Shared Resource with Improper ...
	"CWE-363":  "race-condition", // Race Condition Enabling Link Following
	"CWE-364":  "race-condition", // Signal Handler Race Condition
	"CWE-366":  "race-condition", // Race Condition within a Thread
	"CWE-367":  "race-condition", // Time-of-check Time-of-use (TOCTOU) Race Condition
	"CWE-368":  "race-condition", // Context Switching Race Condition
	"CWE-412":  "race-condition", // Unrestricted Externally Accessible Lock
	"CWE-413":  "race-condition", // Improper Resource Locking
	"CWE-414":  "race-condition", // Missing Lock Check
	"CWE-432":  "race-condition", // Dangerous Signal Handler not Disabled During Sensitive Op...
	"CWE-479":  "race-condition", // Signal Handler Use of a Non-reentrant Function
	"CWE-543":  "race-condition", // Use of Singleton Pattern Without Synchronization in a Mul...
	"CWE-558":  "race-condition", // Use of getlogin() in Multithreaded Application
	"CWE-567":  "race-condition", // Unsynchronized Access to Shared Data in a Multithreaded C...
	"CWE-572":  "race-condition", // Call to Thread run() instead of start()
	"CWE-574":  "race-condition", // EJB Bad Practices: Use of Synchronization Primitives
	"CWE-591":  "race-condition", // Sensitive Data Storage in Improperly Locked Memory
	"CWE-609":  "race-condition", // Double-Checked Locking
	"CWE-662":  "race-condition", // Improper Synchronization
	"CWE-663":  "race-condition", // Use of a Non-reentrant Function in a Concurrent Context
	"CWE-667":  "race-condition", // Improper Locking
	"CWE-689":  "race-condition", // Permission Race Condition During Resource Copy
	"CWE-764":  "race-condition", // Multiple Locks of a Critical Resource
	"CWE-765":  "race-condition", // Multiple Unlocks of a Critical Resource
	"CWE-820":  "race-condition", // Missing Synchronization
	"CWE-821":  "race-condition", // Incorrect Synchronization
	"CWE-828":  "race-condition", // Signal Handler with Functionality that is not Asynchronou...
	"CWE-831":  "race-condition", // Signal Handler Function Associated with Multiple Signals
	"CWE-832":  "race-condition", // Unlock of a Resource that is not Locked
	"CWE-833":  "race-condition", // Deadlock
	"CWE-1058": "race-condition", // Invokable Control Element in Multi-Thread Context with no...
	"CWE-1088": "race-condition", // Synchronous Access of Remote Resource without Timeout
	"CWE-1096": "race-condition", // Singleton Class Instance Creation without Proper Locking ...
	"CWE-1223": "race-condition", // Race Condition for Write-Once Attributes
	"CWE-1232": "race-condition", // Improper Lock Behavior After Power State Transition
	"CWE-1234": "race-condition", // Hardware Internal or Debug Modes Allow Override of Locks
	"CWE-1264": "race-condition", // Hardware Logic with Insecure De-Synchronization between C...
	"CWE-1265": "race-condition", // Unintended Reentrant Invocation of Non-reentrant Code Via...
	"CWE-1298": "race-condition", // Hardware Logic Contains Race Conditions

	// Resource Consumption
	"CWE-400":  "resource-consumption", // Uncontrolled Resource Consumption
	"CWE-405":  "resource-consumption", // Asymmetric Resource Consumption (Amplification)
	"CWE-406":  "resource-consumption", // Insufficient Control of Network Message Volume (Network A...
	"CWE-407":  "resource-consumption", // Inefficient Algorithmic Complexity
	"CWE-408":  "resource-consumption", // Incorrect Behavior Order: Early Amplification
	"CWE-409":  "resource-consumption", // Improper Handling of Highly Compressed Data (Data Amplifi...
	"CWE-770":  "resource-consumption", // Allocation of Resources Without Limits or Throttling
	"CWE-771":  "resource-consumption", // Missing Reference to Active Allocated Resource
	"CWE-773":  "resource-consumption", // Missing Reference to Active File Descriptor or Handle
	"CWE-774":  "resource-consumption", // Allocation of File Descriptors or Handles Without Limits ...
	"CWE-779":  "resource-consumption", // Logging of Excessive Data
	"CWE-789":  "resource-consumption", // Memory Allocation with Excessive Size Value
	"CWE-799":  "resource-consumption", // Improper Control of Interaction Frequency
	"CWE-837":  "resource-consumption", // Improper Enforcement of a Single, Unique Action
	"CWE-920":  "resource-consumption", // Improper Restriction of Power Consumption
	"CWE-1042": "resource-consumption", // Static Member Data Element outside of a Singleton Class E...
	"CWE-1046": "resource-consumption", // Creation of Immutable Text Using String Concatenation
	"CWE-1049": "resource-consumption", // Excessive Data Query Operations in a Large Data Table
	"CWE-1050": "resource-consumption", // Excessive Platform Resource Consumption within a Loop
	"CWE-1063": "resource-consumption", // Creation of Class Instance within a Static Code Block
	"CWE-1067": "resource-consumption", // Excessive Execution of Sequential Searches of Data Resource
	"CWE-1072": "resource-consumption", // Data Resource Access without Use of Connection Pooling
	"CWE-1073": "resource-consumption", // Non-SQL Invokable Control Element with Excessive Number o...
	"CWE-1084": "resource-consumption", // Invokable Control Element with Excessive File or Data Acc...
	"CWE-1089": "resource-consumption", // Large Data Table with Excessive Number of Indices
	"CWE-1094": "resource-consumption", // Excessive Index Range Scan for a Data Resource
	"CWE-1176": "resource-consumption", // Inefficient CPU Computation
	"CWE-1235": "resource-consumption", // Incorrect Use of Autoboxing and Unboxing for Performance ...
	"CWE-1246": "resource-consumption", // Improper Write Handling in Limited-write Non-Volatile Mem...
	"CWE-1325": "resource-consumption", // Improperly Controlled Sequential Memory Allocation
	"CWE-1333": "resource-consumption", // Inefficient Regular Expression Complexity

	// Resource Management
	"CWE-226":  "resource-management", // Sensitive Information in Resource Not Removed Before Reuse
	"CWE-244":  "resource-management", // Improper Clearing of Heap Memory Before Release ('Heap In...
	"CWE-401":  "resource-management", // Missing Release of Memory after Effective Lifetime
	"CWE-404":  "resource-management", // Improper Resource Shutdown or Release
	"CWE-459":  "resource-management", // Incomplete Cleanup
	"CWE-460":  "resource-management", // Improper Cleanup on Thrown Exception
	"CWE-568":  "resource-management", // finalize() Method Without super.finalize()
	"CWE-590":  "resource-management", // Free of Memory not on the Heap
	"CWE-761":  "resource-management", // Free of Pointer not at Start of Buffer
	"CWE-762":  "resource-management", // Mismatched Memory Management Routines
	"CWE-763":  "resource-management", // Release of Invalid Pointer or Reference
	"CWE-772":  "resource-management", // Missing Release of Resource after Effective Lifetime
	"CWE-775":  "resource-management", // Missing Release of File Descriptor or Handle after Effect...
	"CWE-1091": "resource-management", // Use of Object without Invoking Destructor Method
	"CWE-1239": "resource-management", // Improper Zeroization of Hardware Register
	"CWE-1266": "resource-management", // Improper Scrubbing of Sensitive Data from Decommissioned ...
	"CWE-1272": "resource-management", // Sensitive Information Uncleared Before Debug/Power State ...
	"CWE-1301": "resource-management", // Insufficient or Incomplete Data Removal within Hardware C...
	"CWE-1330": "resource-management", // Remanent Data Readable after Memory Erase
	"CWE-1342": "resource-management", // Information Exposure through Microarchitectural State aft...

	// Denial of Service
	"CWE-674":  "denial-of-service", // Uncontrolled Recursion
	"CWE-834":  "denial-of-service", // Excessive Iteration
	"CWE-835":  "denial-of-service", // Loop with Unreachable Exit Condition ('Infinite Loop')
	"CWE-1322": "denial-of-service", // Use of Blocking Code in Single-threaded, Non-blocking Con...

	// Memory Corruption
	"CWE-119": "memory-corruption", // Improper Restriction of Operations within the Bounds of a...
	"CWE-120": "memory-corruption", // Buffer Copy without Checking Size of Input ('Classic Buff...
	"CWE-121": "memory-corruption", // Stack-based Buffer Overflow
	"CWE-122": "memory-corruption", // Heap-based Buffer Overflow
	"CWE-787": "memory-corruption", // Out-of-bounds Write

	// Use After Free
	"CWE-416": "use-after-free", // Use After Free

	// Null Pointer Dereference
	"CWE-476": "null-pointer", // NULL Pointer Dereference

	// Integer Overflow
	"CWE-190": "integer-overflow", // Integer Overflow or Wraparound
	"CWE-191": "integer-overflow", // Integer Underflow (Wrap or Wraparound)

	// Log Injection
	"CWE-117": "log-injection", // Improper Output Neutralization for Logs

	// Logging
	"CWE-778": "logging", // Insufficient Logging

	// Vulnerable Third-Party Component
	"CWE-1104": "vulnerable-component", // Use of Unmaintained Third Party Components
	"CWE-1277": "vulnerable-component", // Firmware Not Updateable
	"CWE-1310": "vulnerable-component", // Missing Ability to Patch ROM Code
	"CWE-1329": "vulnerable-component", // Reliance on Component That is Not Updateable
	"CWE-1357": "vulnerable-component", // Reliance on Insufficiently Trustworthy Component
	"CWE-1395": "vulnerable-component", // Dependency on Vulnerable Third-Party Component

	// Debug Code
	"CWE-11":  "debug-code", // ASP.NET Misconfiguration: Creating Debug Binary
	"CWE-489": "debug-code", // Active Debug Code

	// Malicious Code
	"CWE-506": "malicious-code", // Embedded Malicious Code
	"CWE-507": "malicious-code", // Trojan Horse
	"CWE-508": "malicious-code", // Non-Replicating Malicious Code
	"CWE-509": "malicious-code", // Replicating Malicious Code (Virus or Worm)
	"CWE-510": "malicious-code", // Trapdoor
	"CWE-511": "malicious-code", // Logic/Time Bomb
	"CWE-512": "malicious-code", // Spyware

	// Hidden Functionality
	"CWE-912":  "hidden-functionality", // Hidden Functionality
	"CWE-1242": "hidden-functionality", // Inclusion of Undocumented Features or Chicken Bits

	// Error Handling
	"CWE-7":    "error-handling", // J2EE Misconfiguration: Missing Custom Error Page
	"CWE-12":   "error-handling", // ASP.NET Misconfiguration: Missing Custom Error Page
	"CWE-228":  "error-handling", // Improper Handling of Syntactically Invalid Structure
	"CWE-229":  "error-handling", // Improper Handling of Values
	"CWE-230":  "error-handling", // Improper Handling of Missing Values
	"CWE-231":  "error-handling", // Improper Handling of Extra Values
	"CWE-232":  "error-handling", // Improper Handling of Undefined Values
	"CWE-233":  "error-handling", // Improper Handling of Parameters
	"CWE-234":  "error-handling", // Failure to Handle Missing Parameter
	"CWE-235":  "error-handling", // Improper Handling of Extra Parameters
	"CWE-236":  "error-handling", // Improper Handling of Undefined Parameters
	"CWE-237":  "error-handling", // Improper Handling of Structural Elements
	"CWE-238":  "error-handling", // Improper Handling of Incomplete Structural Elements
	"CWE-239":  "error-handling", // Failure to Handle Incomplete Element
	"CWE-240":  "error-handling", // Improper Handling of Inconsistent Structural Elements
	"CWE-241":  "error-handling", // Improper Handling of Unexpected Data Type
	"CWE-248":  "error-handling", // Uncaught Exception
	"CWE-252":  "error-handling", // Unchecked Return Value
	"CWE-253":  "error-handling", // Incorrect Check of Function Return Value
	"CWE-280":  "error-handling", // Improper Handling of Insufficient Permissions or Privileges
	"CWE-390":  "error-handling", // Detection of Error Condition Without Action
	"CWE-391":  "error-handling", // Unchecked Error Condition
	"CWE-392":  "error-handling", // Missing Report of Error Condition
	"CWE-393":  "error-handling", // Return of Wrong Status Code
	"CWE-394":  "error-handling", // Unexpected Status Code or Return Value
	"CWE-395":  "error-handling", // Use of NullPointerException Catch to Detect NULL Pointer ...
	"CWE-396":  "error-handling", // Declaration of Catch for Generic Exception
	"CWE-397":  "error-handling", // Declaration of Throws for Generic Exception
	"CWE-455":  "error-handling", // Non-exit on Failed Initialization
	"CWE-544":  "error-handling", // Missing Standardized Error Handling Mechanism
	"CWE-600":  "error-handling", // Uncaught Exception in Servlet
	"CWE-636":  "error-handling", // Not Failing Securely ('Failing Open')
	"CWE-690":  "error-handling", // Unchecked Return Value to NULL Pointer Dereference
	"CWE-703":  "error-handling", // Improper Check or Handling of Exceptional Conditions
	"CWE-754":  "error-handling", // Improper Check for Unusual or Exceptional Conditions
	"CWE-755":  "error-handling", // Improper Handling of Exceptional Conditions
	"CWE-756":  "error-handling", // Missing Custom Error Page
	"CWE-1247": "error-handling", // Improper Protection Against Voltage and Clock Glitches
	"CWE-1261": "error-handling", // Improper Handling of Single Event Upsets
	"CWE-1332": "error-handling", // Improper Handling of Faults that Lead to Instruction Skips
	"CWE-1351": "error-handling", // Improper Handling of Hardware Behavior in Exceptionally C...
	"CWE-1384": "error-handling", // Improper Handling of Physical or Environmental Conditions

	// Output Encoding
	"CWE-116": "output-encoding", // Improper Encoding or Escaping of Output
	"CWE-644": "output-encoding", // Improper Neutralization of HTTP Headers for Scripting Syntax
	"CWE-838": "output-encoding", // Inappropriate Encoding for Output Context

	// Encoding
	"CWE-172": "encoding", // Encoding Error
	"CWE-173": "encoding", // Improper Handling of Alternate Encoding
	"CWE-174": "encoding", // Double Decoding of the Same Data
	"CWE-175": "encoding", // Improper Handling of Mixed Encoding
	"CWE-176": "encoding", // Improper Handling of Unicode Encoding
	"CWE-177": "encoding", // Improper Handling of URL Encoding (Hex Encoding)

	// Incorrect Comparison
	"CWE-184":  "incorrect-comparison", // Incomplete List of Disallowed Inputs
	"CWE-185":  "incorrect-comparison", // Incorrect Regular Expression
	"CWE-186":  "incorrect-comparison", // Overly Restrictive Regular Expression
	"CWE-187":  "incorrect-comparison", // Partial String Comparison
	"CWE-478":  "incorrect-comparison", // Missing Default Case in Multiple Condition Expression
	"CWE-486":  "incorrect-comparison", // Comparison of Classes by Name
	"CWE-581":  "incorrect-comparison", // Object Model Violation: Just One of Equals and Hashcode D...
	"CWE-595":  "incorrect-comparison", // Comparison of Object References Instead of Object Contents
	"CWE-597":  "incorrect-comparison", // Use of Wrong Operator in String Comparison
	"CWE-625":  "incorrect-comparison", // Permissive Regular Expression
	"CWE-692":  "incorrect-comparison", // Incomplete Denylist to Cross-Site Scripting
	"CWE-697":  "incorrect-comparison", // Incorrect Comparison
	"CWE-777":  "incorrect-comparison", // Regular Expression without Anchors
	"CWE-839":  "incorrect-comparison", // Numeric Range Comparison Without Minimum Check
	"CWE-1023": "incorrect-comparison", // Incomplete Comparison with Missing Factors
	"CWE-1024": "incorrect-comparison", // Comparison of Incompatible Types
	"CWE-1025": "incorrect-comparison", // Comparison Using Wrong Factors
	"CWE-1039": "incorrect-comparison", // Inadequate Detection or Handling of Adversarial Input Per...
	"CWE-1077": "incorrect-comparison", // Floating Point Comparison with Incorrect Operator
	"CWE-1097": "incorrect-comparison", // Persistent Storable Data Element without Associated Compa...

	// Type Confusion
	"CWE-192":  "type-confusion", // Integer Coercion Error
	"CWE-194":  "type-confusion", // Unexpected Sign Extension
	"CWE-195":  "type-confusion", // Signed to Unsigned Conversion Error
	"CWE-196":  "type-confusion", // Unsigned to Signed Conversion Error
	"CWE-197":  "type-confusion", // Numeric Truncation Error
	"CWE-588":  "type-confusion", // Attempt to Access Child of a Non-structure Pointer
	"CWE-681":  "type-confusion", // Incorrect Conversion between Numeric Types
	"CWE-704":  "type-confusion", // Incorrect Type Conversion or Cast
	"CWE-843":  "type-confusion", // Access of Resource Using Incompatible Type ('Type Confusi...
	"CWE-1389": "type-confusion", // Incorrect Parsing of Numbers with Different Radices

	// Control Flow
	"CWE-382":  "control-flow", // J2EE Bad Practices: Use of System.exit()
	"CWE-430":  "control-flow", // Deployment of Wrong Handler
	"CWE-431":  "control-flow", // Missing Handler
	"CWE-480":  "control-flow", // Use of Incorrect Operator
	"CWE-481":  "control-flow", // Assigning instead of Comparing
	"CWE-482":  "control-flow", // Comparing instead of Assigning
	"CWE-483":  "control-flow", // Incorrect Block Delimitation
	"CWE-484":  "control-flow", // Omitted Break Statement in Switch
	"CWE-584":  "control-flow", // Return Inside Finally Block
	"CWE-617":  "control-flow", // Reachable Assertion
	"CWE-670":  "control-flow", // Always-Incorrect Control Flow Implementation
	"CWE-691":  "control-flow", // Insufficient Control Flow Management
	"CWE-696":  "control-flow", // Incorrect Behavior Order
	"CWE-698":  "control-flow", // Execution After Redirect (EAR)
	"CWE-705":  "control-flow", // Incorrect Control Flow Scoping
	"CWE-768":  "control-flow", // Incorrect Short Circuit Evaluation
	"CWE-783":  "control-flow", // Operator Precedence Logic Error
	"CWE-841":  "control-flow", // Improper Enforcement of Behavioral Workflow
	"CWE-1190": "control-flow", // DMA Device Enabled Too Early in Boot Phase
	"CWE-1193": "control-flow", // Power-On of Untrusted Execution Core Before Enabling Fabr...
	"CWE-1279": "control-flow", // Cryptographic Operations are run Before Supporting Units ...
	"CWE-1281": "control-flow", // Sequence of Processor Instructions Leads to Unexpected Be...

	// Initialization
	"CWE-454":  "initialization", // External Initialization of Trusted Variables or Data Stores
	"CWE-456":  "initialization", // Missing Initialization of a Variable
	"CWE-457":  "initialization", // Use of Uninitialized Variable
	"CWE-665":  "initialization", // Improper Initialization
	"CWE-908":  "initialization", // Use of Uninitialized Resource
	"CWE-909":  "initialization", // Missing Initialization of Resource
	"CWE-1051": "initialization", // Initialization with Hard-Coded Network Resource Configura...
	"CWE-1052": "initialization", // Excessive Use of Hard-Coded Literals in Initialization
	"CWE-1221": "initialization", // Incorrect Register Defaults or Module Parameters
	"CWE-1271": "initialization", // Uninitialized Value on Reset for Registers Holding Securi...
	"CWE-1419": "initialization", // Incorrect Initialization of Resource
	"CWE-1434": "initialization", // Insecure Setting of Generative AI/ML Model Inference Para...

	// Design Principles
	"CWE-447":  "design-principles", // Unimplemented or Unsupported Feature in UI
	"CWE-637":  "design-principles", // Unnecessary Complexity in Protection Mechanism (Not Using...
	"CWE-653":  "design-principles", // Improper Isolation or Compartmentalization
	"CWE-654":  "design-principles", // Reliance on a Single Factor in a Security Decision
	"CWE-655":  "design-principles", // Insufficient Psychological Acceptability
	"CWE-656":  "design-principles", // Reliance on Security Through Obscurity
	"CWE-657":  "design-principles", // Violation of Secure Design Principles
	"CWE-671":  "design-principles", // Lack of Administrator Control over Security
	"CWE-1192": "design-principles", // Improper Identifier for IP Block used in System-On-Chip (...

	// Client-Side Enforcement
	"CWE-602": "client-side-enforcement", // Client-Side Enforcement of Server-Side Security

	// Resource Lifecycle
	"CWE-59":   "resource-lifecycle", // Improper Link Resolution Before File Access ('Link Follow...
	"CWE-61":   "resource-lifecycle", // UNIX Symbolic Link (Symlink) Following
	"CWE-62":   "resource-lifecycle", // UNIX Hard Link
	"CWE-64":   "resource-lifecycle", // Windows Shortcut Following (.LNK)
	"CWE-65":   "resource-lifecycle", // Windows Hard Link
	"CWE-66":   "resource-lifecycle", // Improper Handling of File Names that Identify Virtual Res...
	"CWE-67":   "resource-lifecycle", // Improper Handling of Windows Device Names
	"CWE-69":   "resource-lifecycle", // Improper Handling of Windows ::DATA Alternate Data Stream
	"CWE-72":   "resource-lifecycle", // Improper Handling of Apple HFS+ Alternate Data Stream Path
	"CWE-98":   "resource-lifecycle", // Improper Control of Filename for Include/Require Statemen...
	"CWE-118":  "resource-lifecycle", // Incorrect Access of Indexable Resource ('Range Error')
	"CWE-178":  "resource-lifecycle", // Improper Handling of Case Sensitivity
	"CWE-212":  "resource-lifecycle", // Improper Removal of Sensitive Information Before Storage ...
	"CWE-221":  "resource-lifecycle", // Information Loss or Omission
	"CWE-222":  "resource-lifecycle", // Truncation of Security-relevant Information
	"CWE-223":  "resource-lifecycle", // Omission of Security-relevant Information
	"CWE-224":  "resource-lifecycle", // Obscured Security-relevant Information by Alternate Name
	"CWE-243":  "resource-lifecycle", // Creation of chroot Jail Without Changing Working Directory
	"CWE-324":  "resource-lifecycle", // Use of a Key Past its Expiration Date
	"CWE-356":  "resource-lifecycle", // Product UI does not Warn User of Unsafe Actions
	"CWE-372":  "resource-lifecycle", // Incomplete Internal State Distinction
	"CWE-385":  "resource-lifecycle", // Covert Timing Channel
	"CWE-386":  "resource-lifecycle", // Symbolic Name not Mapping to Correct Object
	"CWE-410":  "resource-lifecycle", // Insufficient Resource Pool
	"CWE-451":  "resource-lifecycle", // User Interface (UI) Misrepresentation of Critical Informa...
	"CWE-471":  "resource-lifecycle", // Modification of Assumed-Immutable Data (MAID)
	"CWE-473":  "resource-lifecycle", // PHP External Variable Modification
	"CWE-487":  "resource-lifecycle", // Reliance on Package-level Scope
	"CWE-495":  "resource-lifecycle", // Private Data Structure Returned From A Public Method
	"CWE-496":  "resource-lifecycle", // Public Data Assigned to Private Array-Typed Field
	"CWE-501":  "resource-lifecycle", // Trust Boundary Violation
	"CWE-514":  "resource-lifecycle", // Covert Channel
	"CWE-515":  "resource-lifecycle", // Covert Storage Channel
	"CWE-580":  "resource-lifecycle", // clone() Method Without super.clone()
	"CWE-605":  "resource-lifecycle", // Multiple Binds to the Same Port
	"CWE-607":  "resource-lifecycle", // Public Static Final Field References Mutable Object
	"CWE-610":  "resource-lifecycle", // Externally Controlled Reference to a Resource in Another ...
	"CWE-613":  "resource-lifecycle", // Insufficient Session Expiration
	"CWE-664":  "resource-lifecycle", // Improper Control of a Resource Through its Lifetime
	"CWE-666":  "resource-lifecycle", // Operation on Resource in Wrong Phase of Lifetime
	"CWE-669":  "resource-lifecycle", // Incorrect Resource Transfer Between Spheres
	"CWE-672":  "resource-lifecycle", // Operation on a Resource after Expiration or Release
	"CWE-673":  "resource-lifecycle", // External Influence of Sphere Definition
	"CWE-706":  "resource-lifecycle", // Use of Incorrectly-Resolved Name or Reference
	"CWE-826":  "resource-lifecycle", // Premature Release of Resource During Expected Lifetime
	"CWE-827":  "resource-lifecycle", // Improper Control of Document Type Definition
	"CWE-829":  "resource-lifecycle", // Inclusion of Functionality from Untrusted Control Sphere
	"CWE-830":  "resource-lifecycle", // Inclusion of Web Functionality from an Untrusted Source
	"CWE-910":  "resource-lifecycle", // Use of Expired File Descriptor
	"CWE-911":  "resource-lifecycle", // Improper Update of Reference Count
	"CWE-913":  "resource-lifecycle", // Improper Control of Dynamically-Managed Code Resources
	"CWE-921":  "resource-lifecycle", // Storage of Sensitive Data in a Mechanism without Access C...
	"CWE-922":  "resource-lifecycle", // Insecure Storage of Sensitive Information
	"CWE-1007": "resource-lifecycle", // Insufficient Visual Distinction of Homoglyphs Presented t...
	"CWE-1229": "resource-lifecycle", // Creation of Emergent Resource
	"CWE-1249": "resource-lifecycle", // Application-Level Admin Tool with Inconsistent View of Un...
	"CWE-1250": "resource-lifecycle", // Improper Preservation of Consistency Between Independent ...
	"CWE-1251": "resource-lifecycle", // Mirrored Regions with Different Values
	"CWE-1258": "resource-lifecycle", // Exposure of Sensitive System Information Due to Uncleared...
	"CWE-1386": "resource-lifecycle", // Insecure Operation on Windows Junction / Mount Point
	"CWE-1420": "resource-lifecycle", // Exposure of Sensitive Information during Transient Execution
	"CWE-1421": "resource-lifecycle", // Exposure of Sensitive Information in Shared Microarchitec...
	"CWE-1422": "resource-lifecycle", // Exposure of Sensitive Information caused by Incorrect Dat...
	"CWE-1423": "resource-lifecycle", // Exposure of Sensitive Information caused by Shared Microa...
	"CWE-1429": "resource-lifecycle", // Missing Security-Relevant Feedback for Unexecuted Operati...

	// Improper Neutralization (General)
	"CWE-182":  "improper-neutralization", // Collapse of Data into Unsafe Value
	"CWE-463":  "improper-neutralization", // Deletion of Data Structure Sentinel
	"CWE-707":  "improper-neutralization", // Improper Neutralization
	"CWE-1426": "improper-neutralization", // Improper Validation of Generative AI Output

	// Coding Standards
	"CWE-14":   "coding-standards", // Compiler Removal of Code to Clear Buffers
	"CWE-188":  "coding-standards", // Reliance on Data/Memory Layout
	"CWE-198":  "coding-standards", // Use of Incorrect Byte Ordering
	"CWE-242":  "coding-standards", // Use of Inherently Dangerous Function
	"CWE-245":  "coding-standards", // J2EE Bad Practices: Direct Management of Connections
	"CWE-246":  "coding-standards", // J2EE Bad Practices: Direct Use of Sockets
	"CWE-358":  "coding-standards", // Improperly Implemented Security Check for Standard
	"CWE-383":  "coding-standards", // J2EE Bad Practices: Direct Use of Threads
	"CWE-440":  "coding-standards", // Expected Behavior Violation
	"CWE-446":  "coding-standards", // UI Discrepancy for Security Feature
	"CWE-448":  "coding-standards", // Obsolete Feature in UI
	"CWE-449":  "coding-standards", // The UI Performs the Wrong Action
	"CWE-474":  "coding-standards", // Use of Function with Inconsistent Implementations
	"CWE-475":  "coding-standards", // Undefined Behavior for Input to API
	"CWE-477":  "coding-standards", // Use of Obsolete Function
	"CWE-546":  "coding-standards", // Suspicious Comment
	"CWE-547":  "coding-standards", // Use of Hard-coded, Security-relevant Constants
	"CWE-560":  "coding-standards", // Use of umask() with chmod-style Argument
	"CWE-561":  "coding-standards", // Dead Code
	"CWE-562":  "coding-standards", // Return of Stack Variable Address
	"CWE-563":  "coding-standards", // Assignment to Variable without Use
	"CWE-570":  "coding-standards", // Expression is Always False
	"CWE-571":  "coding-standards", // Expression is Always True
	"CWE-573":  "coding-standards", // Improper Following of Specification by Caller
	"CWE-575":  "coding-standards", // EJB Bad Practices: Use of AWT Swing
	"CWE-576":  "coding-standards", // EJB Bad Practices: Use of Java I/O
	"CWE-577":  "coding-standards", // EJB Bad Practices: Use of Sockets
	"CWE-578":  "coding-standards", // EJB Bad Practices: Use of Class Loader
	"CWE-579":  "coding-standards", // J2EE Bad Practices: Non-serializable Object Stored in Ses...
	"CWE-585":  "coding-standards", // Empty Synchronized Block
	"CWE-586":  "coding-standards", // Explicit Call to Finalize()
	"CWE-589":  "coding-standards", // Call to Non-ubiquitous API
	"CWE-594":  "coding-standards", // J2EE Framework: Saving Unserializable Objects to Disk
	"CWE-628":  "coding-standards", // Function Call with Incorrectly Specified Arguments
	"CWE-675":  "coding-standards", // Multiple Operations on Resource in Single-Operation Context
	"CWE-676":  "coding-standards", // Use of Potentially Dangerous Function
	"CWE-683":  "coding-standards", // Function Call With Incorrect Order of Arguments
	"CWE-684":  "coding-standards", // Incorrect Provision of Specified Functionality
	"CWE-685":  "coding-standards", // Function Call With Incorrect Number of Arguments
	"CWE-686":  "coding-standards", // Function Call With Incorrect Argument Type
	"CWE-687":  "coding-standards", // Function Call With Incorrectly Specified Argument Value
	"CWE-688":  "coding-standards", // Function Call With Incorrect Variable or Reference as Arg...
	"CWE-695":  "coding-standards", // Use of Low-Level Functionality
	"CWE-710":  "coding-standards", // Improper Adherence to Coding Standards
	"CWE-733":  "coding-standards", // Compiler Optimization Removal or Modification of Security...
	"CWE-758":  "coding-standards", // Reliance on Undefined, Unspecified, or Implementation-Def...
	"CWE-1037": "coding-standards", // Processor Optimization Removal or Modification of Securit...
	"CWE-1038": "coding-standards", // Insecure Automated Optimizations
	"CWE-1041": "coding-standards", // Use of Redundant Code
	"CWE-1043": "coding-standards", // Data Element Aggregating an Excessively Large Number of N...
	"CWE-1044": "coding-standards", // Architecture with Number of Horizontal Layers Outside of ...
	"CWE-1045": "coding-standards", // Parent Class with a Virtual Destructor and a Child Class ...
	"CWE-1047": "coding-standards", // Modules with Circular Dependencies
	"CWE-1048": "coding-standards", // Invokable Control Element with Large Number of Outward Calls
	"CWE-1053": "coding-standards", // Missing Documentation for Design
	"CWE-1054": "coding-standards", // Invocation of a Control Element at an Unnecessarily Deep ...
	"CWE-1055": "coding-standards", // Multiple Inheritance from Concrete Classes
	"CWE-1056": "coding-standards", // Invokable Control Element with Variadic Parameters
	"CWE-1057": "coding-standards", // Data Access Operations Outside of Expected Data Manager C...
	"CWE-1059": "coding-standards", // Insufficient Technical Documentation
	"CWE-1060": "coding-standards", // Excessive Number of Inefficient Server-Side Data Accesses
	"CWE-1061": "coding-standards", // Insufficient Encapsulation
	"CWE-1062": "coding-standards", // Parent Class with References to Child Class
	"CWE-1064": "coding-standards", // Invokable Control Element with Signature Containing an Ex...
	"CWE-1065": "coding-standards", // Runtime Resource Management Control Element in a Componen...
	"CWE-1066": "coding-standards", // Missing Serialization Control Element
	"CWE-1068": "coding-standards", // Inconsistency Between Implementation and Documented Design
	"CWE-1069": "coding-standards", // Empty Exception Block
	"CWE-1070": "coding-standards", // Serializable Data Element Containing non-Serializable Ite...
	"CWE-1071": "coding-standards", // Empty Code Block
	"CWE-1074": "coding-standards", // Class with Excessively Deep Inheritance
	"CWE-1075": "coding-standards", // Unconditional Control Flow Transfer outside of Switch Block
	"CWE-1076": "coding-standards", // Insufficient Adherence to Expected Conventions
	"CWE-1078": "coding-standards", // Inappropriate Source Code Style or Formatting
	"CWE-1079": "coding-standards", // Parent Class without Virtual Destructor Method
	"CWE-1080": "coding-standards", // Source Code File with Excessive Number of Lines of Code
	"CWE-1082": "coding-standards", // Class Instance Self Destruction Control Element
	"CWE-1083": "coding-standards", // Data Access from Outside Expected Data Manager Component
	"CWE-1085": "coding-standards", // Invokable Control Element with Excessive Volume of Commen...
	"CWE-1086": "coding-standards", // Class with Excessive Number of Child Classes
	"CWE-1087": "coding-standards", // Class with Virtual Method without a Virtual Destructor
	"CWE-1090": "coding-standards", // Method Containing Access of a Member Element from Another...
	"CWE-1092": "coding-standards", // Use of Same Invokable Control Element in Multiple Archite...
	"CWE-1093": "coding-standards", // Excessively Complex Data Representation
	"CWE-1095": "coding-standards", // Loop Condition Value Update within the Loop
	"CWE-1098": "coding-standards", // Data Element containing Pointer Item without Proper Copy ...
	"CWE-1099": "coding-standards", // Inconsistent Naming Conventions for Identifiers
	"CWE-1100": "coding-standards", // Insufficient Isolation of System-Dependent Functions
	"CWE-1101": "coding-standards", // Reliance on Runtime Component in Generated Code
	"CWE-1102": "coding-standards", // Reliance on Machine-Dependent Data Representation
	"CWE-1103": "coding-standards", // Use of Platform-Dependent Third Party Components
	"CWE-1105": "coding-standards", // Insufficient Encapsulation of Machine-Dependent Functiona...
	"CWE-1106": "coding-standards", // Insufficient Use of Symbolic Constants
	"CWE-1107": "coding-standards", // Insufficient Isolation of Symbolic Constant Definitions
	"CWE-1108": "coding-standards", // Excessive Reliance on Global Variables
	"CWE-1109": "coding-standards", // Use of Same Variable for Multiple Purposes
	"CWE-1110": "coding-standards", // Incomplete Design Documentation
	"CWE-1111": "coding-standards", // Incomplete I/O Documentation
	"CWE-1112": "coding-standards", // Incomplete Documentation of Program Execution
	"CWE-1113": "coding-standards", // Inappropriate Comment Style
	"CWE-1114": "coding-standards", // Inappropriate Whitespace Style
	"CWE-1115": "coding-standards", // Source Code Element without Standard Prologue
	"CWE-1116": "coding-standards", // Inaccurate Source Code Comments
	"CWE-1117": "coding-standards", // Callable with Insufficient Behavioral Summary
	"CWE-1118": "coding-standards", // Insufficient Documentation of Error Handling Techniques
	"CWE-1119": "coding-standards", // Excessive Use of Unconditional Branching
	"CWE-1120": "coding-standards", // Excessive Code Complexity
	"CWE-1121": "coding-standards", // Excessive McCabe Cyclomatic Complexity
	"CWE-1122": "coding-standards", // Excessive Halstead Complexity
	"CWE-1123": "coding-standards", // Excessive Use of Self-Modifying Code
	"CWE-1124": "coding-standards", // Excessively Deep Nesting
	"CWE-1125": "coding-standards", // Excessive Attack Surface
	"CWE-1126": "coding-standards", // Declaration of Variable with Unnecessarily Wide Scope
	"CWE-1127": "coding-standards", // Compilation with Insufficient Warnings or Errors
	"CWE-1164": "coding-standards", // Irrelevant Code
	"CWE-1177": "coding-standards", // Use of Prohibited Code
	"CWE-1209": "coding-standards", // Failure to Disable Reserved Bits
	"CWE-1245": "coding-standards", // Improper Finite State Machines (FSMs) in Hardware Logic
	"CWE-1341": "coding-standards", // Multiple Releases of Same Resource or Handle

	// Incorrect Calculation
	"CWE-128":  "incorrect-calculation", // Wrap-around Error
	"CWE-131":  "incorrect-calculation", // Incorrect Calculation of Buffer Size
	"CWE-135":  "incorrect-calculation", // Incorrect Calculation of Multi-Byte String Length
	"CWE-193":  "incorrect-calculation", // Off-by-one Error
	"CWE-369":  "incorrect-calculation", // Divide By Zero
	"CWE-467":  "incorrect-calculation", // Use of sizeof() on a Pointer Type
	"CWE-468":  "incorrect-calculation", // Incorrect Pointer Scaling
	"CWE-469":  "incorrect-calculation", // Use of Pointer Subtraction to Determine Size
	"CWE-682":  "incorrect-calculation", // Incorrect Calculation
	"CWE-1335": "incorrect-calculation", // Incorrect Bitwise Shift of Integer
	"CWE-1339": "incorrect-calculation", // Insufficient Precision or Accuracy of a Real Number

	// Interaction Errors
	"CWE-115": "interaction-errors", // Misinterpretation of Input
	"CWE-435": "interaction-errors", // Improper Interaction Between Multiple Correctly-Behaving ...
	"CWE-436": "interaction-errors", // Interpretation Conflict
	"CWE-437": "interaction-errors", // Incomplete Model of Endpoint Features
	"CWE-439": "interaction-errors", // Behavioral Change in New Version or Environment
	"CWE-444": "interaction-errors", // Inconsistent Interpretation of HTTP Requests ('HTTP Reque...
	"CWE-650": "interaction-errors", // Trusting HTTP Permission Methods on the Server Side

	// Protection Mechanism Failure
	"CWE-357":  "protection-mechanism-failure", // Insufficient UI Warning of Dangerous Operations
	"CWE-450":  "protection-mechanism-failure", // Multiple Interpretations of UI Input
	"CWE-693":  "protection-mechanism-failure", // Protection Mechanism Failure
	"CWE-757":  "protection-mechanism-failure", // Selection of Less-Secure Algorithm During Negotiation ('A...
	"CWE-807":  "protection-mechanism-failure", // Reliance on Untrusted Inputs in a Security Decision
	"CWE-1248": "protection-mechanism-failure", // Semiconductor Defects in Hardware Logic with Security-Sen...
	"CWE-1253": "protection-mechanism-failure", // Incorrect Selection of Fuse Values
	"CWE-1269": "protection-mechanism-failure", // Product Released in Non-Release Configuration
	"CWE-1278": "protection-mechanism-failure", // Missing Protection Against Hardware Reverse Engineering U...
	"CWE-1291": "protection-mechanism-failure", // Public Key Re-Use for Signing both Debug and Production Code
	"CWE-1318": "protection-mechanism-failure", // Missing Support for Security Features in On-chip Fabrics ...
	"CWE-1319": "protection-mechanism-failure", // Improper Protection against Electromagnetic Fault Injecti...
	"CWE-1326": "protection-mechanism-failure", // Missing Immutable Root of Trust in Hardware
	"CWE-1338": "protection-mechanism-failure", // Improper Protections Against Hardware Overheating

}

// GetCategory returns the vulnerability category for a CWE ID.
// Returns "unknown" if the CWE is not in the mapping.
func GetCategory(cweID string) string {
	if cat, ok := CWECategories[cweID]; ok {
		return cat
	}
	return "unknown"
}

// AreCompatible returns true if two CWE IDs belong to the same category.
// Two unknown CWEs are not considered compatible (both return "unknown" but
// we don't match unknowns together by category).
func AreCompatible(cwe1, cwe2 string) bool {
	cat1 := GetCategory(cwe1)
	cat2 := GetCategory(cwe2)
	if cat1 == "unknown" || cat2 == "unknown" {
		return false
	}
	return cat1 == cat2
}
