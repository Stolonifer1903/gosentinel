// Package descriptions provides centralized vulnerability descriptions indexed by CheckID.
// This ensures consistency across all scanner modules and makes it easy to maintain
// descriptions for current and future checks in a single location.
package descriptions

import "fmt"

type VulnerabilityDescription struct {
	// Category is the OWASP Top 10: 2021 classification (e.g. "A05:2021 - Security Misconfiguration").
	Category string
	// What describes the specific issue that was found.
	What string
	// Why explains the security significance and potential impact.
	Why string
	// Impact describes the real-world consequences if exploited.
	Impact string
}

// DescriptionRegistry maps each CheckID to its structured vulnerability description and category.
// Add new entries here as new scanner modules are implemented.
var DescriptionRegistry = map[CheckID]VulnerabilityDescription{
	// ============================================================================
	// HEADERS (A05:2021 - Security Misconfiguration)
	// ============================================================================
	HeaderHSTSMissing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "HTTP Strict-Transport-Security (HSTS) header is absent from the response.",
		Why:      "HSTS enforces HTTPS connections and prevents downgrade attacks. Without it, users can be tricked into connecting via HTTP, exposing sensitive data to man-in-the-middle (MITM) attacks.",
		Impact:   "Attackers can intercept unencrypted traffic, stealing session tokens, credentials, or sensitive information transmitted over HTTP.",
	},
	HeaderCSPMissing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "Content-Security-Policy (CSP) header is missing from the response.",
		Why:      "CSP is a critical defense against Cross-Site Scripting (XSS) and data injection attacks. It controls which scripts, stylesheets, and other resources can be loaded, preventing malicious inline scripts.",
		Impact:   "Without CSP, attackers can inject and execute arbitrary JavaScript in the page context, stealing user data, hijacking sessions, or redirecting users to phishing sites.",
	},
	HeaderXFrameOptionsMissing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "X-Frame-Options header is missing from the response.",
		Why:      "This header prevents clickjacking attacks where malicious sites embed your application in invisible iframes to trick users into performing unintended actions.",
		Impact:   "Attackers can frame your application and overlay invisible buttons/forms, causing users to unknowingly grant permissions, transfer funds, or delete accounts.",
	},
	HeaderXContentTypeMissing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "X-Content-Type-Options header is missing from the response.",
		Why:      "Without this header, browsers may guess (sniff) the MIME type of content, which can lead to security vulnerabilities if a user uploads or serves misidentified content as executable.",
		Impact:   "Malicious uploaded files (e.g., images) could be executed as JavaScript by the browser if it sniffs them as text/html, leading to XSS attacks.",
	},
	HeaderReferrerPolicyMissing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "Referrer-Policy header is missing from the response.",
		Why:      "Without controlling the Referrer header, sensitive information in URLs (such as authentication tokens or user identifiers) can leak to third-party sites when users navigate away.",
		Impact:   "Sensitive data in URLs (tokens, IDs, query parameters) is exposed to external websites via the Referer header, potentially revealing user information.",
	},
	HeaderPermissionsPolicyMissing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "Permissions-Policy header is missing from the response.",
		Why:      "This header restricts access to powerful browser features (camera, microphone, geolocation, payment API) that malicious scripts could abuse to spy on users or obtain information.",
		Impact:   "Malicious scripts can access sensitive device capabilities, leading to unauthorized surveillance, information disclosure, or unauthorized payments.",
	},

	// ============================================================================
	// CSRF (A01:2021 - Broken Access Control)
	// ============================================================================
	CSRFTokenMissing: {
		Category: "A01:2021 - Broken Access Control",
		What:     "A POST form was detected without a CSRF (Cross-Site Request Forgery) prevention token.",
		Why:      "CSRF tokens validate that form submissions originate from your application, not from a malicious third-party site. Without them, attackers can trick logged-in users into performing unwanted actions.",
		Impact:   "Attackers can forge requests on behalf of authenticated users, causing them to unknowingly transfer funds, change passwords, delete accounts, or perform other sensitive operations.",
	},

	// ============================================================================
	// SENSITIVE DATA
	// ============================================================================
	SensitiveDataAWSKey: {
		Category: "A02:2021 - Cryptographic Failures",
		What:     "AWS access key identifier (AKIA...) was found exposed in the application response or page source.",
		Why:      "AWS keys are credentials that grant access to cloud resources. Exposed keys can be used to steal data, launch attacks, or incur large charges on your AWS account.",
		Impact:   "Attackers can use exposed AWS keys to access your cloud infrastructure, databases, and storage buckets, leading to data breaches, service disruption, or financial loss.",
	},
	SensitiveDataPrivateKey: {
		Category: "A02:2021 - Cryptographic Failures",
		What:     "A private key (RSA, DSA, or other cryptographic key) was found exposed in the application response.",
		Why:      "Private keys are the foundation of cryptographic security. If exposed, attackers can impersonate your servers, decrypt communications, or forge digital signatures.",
		Impact:   "Compromise of private keys enables man-in-the-middle attacks, message forgery, certificate spoofing, and complete encryption bypass for affected communications.",
	},
	SensitiveDataPassword: {
		Category: "A02:2021 - Cryptographic Failures",
		What:     "A password or password-like credential was found hardcoded or exposed in the application response.",
		Why:      "Hardcoded credentials in source code or HTML comments can be discovered and used to gain unauthorized access to systems or accounts.",
		Impact:   "Attackers can use exposed credentials to gain direct access to user accounts, databases, administrative panels, or other protected systems.",
	},
	SensitiveDataStackTrace: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "Detailed application error/stack traces were exposed in the HTTP response.",
		Why:      "Stack traces reveal internal application structure, file paths, framework versions, and sometimes even source code snippets, enabling attackers to identify vulnerabilities.",
		Impact:   "Information disclosed in stack traces helps attackers identify framework vulnerabilities, find weak code patterns, and craft targeted exploits.",
	},
	SensitiveDataDirectoryListing: {
		Category: "A05:2021 - Security Misconfiguration",
		What:     "Directory listing was exposed (e.g., Index of / directory view).",
		Why:      "Directory listings expose the structure of your application and reveal files that were not intended to be publicly accessible, such as configuration files, backups, or debug logs.",
		Impact:   "Attackers can discover sensitive files, configuration details, backup files, or scripts that may contain vulnerabilities or credentials.",
	},

	// ============================================================================
	// XSS (A03:2021 - Injection)
	// ============================================================================
	XSSReflected: {
		Category: "A03:2021 - Injection",
		What:     "A Cross-Site Scripting (XSS) payload was injected into a request parameter and reflected unescaped in the response.",
		Why:      "Reflected XSS allows attackers to inject and execute arbitrary JavaScript in the context of your application, running with the victim's privileges and access.",
		Impact:   "Attackers can steal session cookies, authentication tokens, user data, or perform actions on behalf of users. Malicious scripts can redirect users to phishing sites or deliver malware.",
	},

	// ============================================================================
	// SQL INJECTION (A03:2021 - Injection)
	// ============================================================================
	SQLiErrorBased: {
		Category: "A03:2021 - Injection",
		What:     "A SQL injection payload was inserted into a query parameter, causing a database error to be reflected in the response.",
		Why:      "SQL injection allows attackers to execute arbitrary SQL queries against your database, potentially extracting sensitive data, modifying records, or compromising the entire database.",
		Impact:   "Attackers can access, modify, or delete any data in your database, bypass authentication, escalate privileges, or potentially gain command execution on the database server.",
	},
	SQLiTimeBased: {
		Category: "A03:2021 - Injection",
		What:     "A SQL injection payload with a time-delay function (e.g., SLEEP) caused a measurable response delay.",
		Why:      "Time-based SQL injection extracts data by measuring response delays, allowing attackers to slowly but reliably extract sensitive information from the database blind.",
		Impact:   "Attackers can extract sensitive data, credentials, or entire database contents through blind SQL injection, even when error messages are suppressed.",
	},

	// ============================================================================
	// SSRF (A10:2021 - Server-Side Request Forgery)
	// ============================================================================
	SSRFInternalIPDisclosure: {
		Category: "A10:2021 - Server-Side Request Forgery",
		What:     "A Server-Side Request Forgery (SSRF) payload pointing to an internal IP address was sent, and internal network content was returned in the response.",
		Why:      "SSRF allows attackers to trick the server into making requests to internal systems, accessing private networks, cloud endpoints (169.254.169.254), or launching attacks from within the trusted network.",
		Impact:   "Attackers can access internal services, steal cloud credentials (AWS metadata), reach databases on private networks, or use the server as a proxy to attack internal infrastructure.",
	},

	// ============================================================================
	// IDOR (A01:2021 - Broken Access Control)
	// ============================================================================
	IDORNumericIDAccess: {
		Category: "A01:2021 - Broken Access Control",
		What:     "A numeric ID in the URL path or parameter could be modified to access other users' resources without authorization checks.",
		Why:      "Insecure Direct Object References (IDOR) occur when object references are not properly validated, allowing attackers to access resources belonging to other users simply by changing an ID.",
		Impact:   "Attackers can view, modify, or delete other users' data, profiles, orders, or sensitive documents by manipulating object references.",
	},

	// ============================================================================
	// BROKEN AUTHENTICATION (A07:2021 - Identification and Authentication Failures)
	// ============================================================================
	AuthDefaultCredentials: {
		Category: "A07:2021 - Identification and Authentication Failures",
		What:     "An authentication attempt with default or common credentials (e.g., admin/admin, test/test) was successful.",
		Why:      "Default credentials are widely known and pose an immediate security risk. Attackers can quickly gain unauthorized access using publicly documented default credentials.",
		Impact:   "Attackers can gain immediate full access to administrative or user accounts without needing to crack passwords, enabling data breaches, account takeovers, and system compromise.",
	},
}

// GetDescription retrieves and formats the structured description for a given CheckID.
// Returns a formatted paragraph combining What/Why/Impact.
// If the CheckID is not found, returns a generic fallback message.
func GetDescription(checkID CheckID) string {
	desc, exists := DescriptionRegistry[checkID]
	if !exists {
		return fmt.Sprintf("A security issue (ID: %s) was detected. Please review the remediation guidance.", checkID)
	}
	return fmt.Sprintf("%s %s %s", desc.What, desc.Why, desc.Impact)
}

// GetCategory returns the OWASP Top 10: 2021 category for the given CheckID.
func GetCategory(checkID CheckID) string {
	desc, exists := DescriptionRegistry[checkID]
	if !exists {
		return "A00:2021 - Unknown Category"
	}
	return desc.Category
}
