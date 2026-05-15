package descriptions

// CheckID is a unique identifier for a specific security check.
// Using constants ensures type safety and IDE autocomplete for check lookups.
type CheckID string

// Header-related check IDs
const (
	HeaderHSTSMissing              CheckID = "HEADER_HSTS_MISSING"
	HeaderCSPMissing               CheckID = "HEADER_CSP_MISSING"
	HeaderXFrameOptionsMissing     CheckID = "HEADER_X_FRAME_OPTIONS_MISSING"
	HeaderXContentTypeMissing      CheckID = "HEADER_X_CONTENT_TYPE_OPTIONS_MISSING"
	HeaderReferrerPolicyMissing    CheckID = "HEADER_REFERRER_POLICY_MISSING"
	HeaderPermissionsPolicyMissing CheckID = "HEADER_PERMISSIONS_POLICY_MISSING"
)

// CSRF-related check IDs
const (
	CSRFTokenMissing CheckID = "CSRF_TOKEN_MISSING"
)

// Sensitive data-related check IDs
const (
	SensitiveDataAWSKey           CheckID = "SENSITIVE_DATA_AWS_KEY"
	SensitiveDataPrivateKey       CheckID = "SENSITIVE_DATA_PRIVATE_KEY"
	SensitiveDataPassword         CheckID = "SENSITIVE_DATA_PASSWORD"
	SensitiveDataStackTrace       CheckID = "SENSITIVE_DATA_STACK_TRACE"
	SensitiveDataDirectoryListing CheckID = "SENSITIVE_DATA_DIRECTORY_LISTING"
)

// XSS-related check IDs
const (
	XSSReflected        CheckID = "XSS_REFLECTED"
	XSSReflectedEscaped CheckID = "XSS_REFLECTED_ESCAPED"
	XSSStored           CheckID = "XSS_STORED"
)

// SQL Injection-related check IDs
const (
	SQLiErrorBased CheckID = "SQLI_ERROR_BASED"
	SQLiTimeBased  CheckID = "SQLI_TIME_BASED"
)

// SSRF-related check IDs
const (
	SSRFInternalIPDisclosure CheckID = "SSRF_INTERNAL_IP_DISCLOSURE"
	SSRFCloudMetadata        CheckID = "SSRF_CLOUD_METADATA"
	SSRFPartialBlind         CheckID = "SSRF_PARTIAL_BLIND"
)

// IDOR-related check IDs
const (
	IDORNumericIDAccess CheckID = "IDOR_NUMERIC_ID_ACCESS"
)

// Authentication and Access Control-related check IDs
const (
	AuthDefaultCredentials            CheckID = "AUTH_DEFAULT_CREDENTIALS"
	AuthHorizontalPrivilegeEscalation CheckID = "AUTH_HORIZONTAL_PRIVILEGE_ESCALATION"
	AuthVerticalPrivilegeEscalation   CheckID = "AUTH_VERTICAL_PRIVILEGE_ESCALATION"
	AuthForcedBrowsing                CheckID = "AUTH_FORCED_BROWSING"
	AuthMethodTampering               CheckID = "AUTH_METHOD_TAMPERING"
	AuthJWTManipulation               CheckID = "AUTH_JWT_MANIPULATION"
	AuthPathTraversalBypass           CheckID = "AUTH_PATH_TRAVERSAL_BYPASS"
	AuthCORSMisconfiguration          CheckID = "AUTH_CORS_MISCONFIGURATION"
)
