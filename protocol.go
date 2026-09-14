package main

const (
	PROTOCOL_VERSION_MAJOR = 3
	PROTOCOL_VERSION_MINOR = 2
	PROTOCOL_VERSION       = (PROTOCOL_VERSION_MAJOR << 16) | PROTOCOL_VERSION_MINOR
)

const (
	Authentication           = 'R'
	BackendKeyData           = 'K'
	BindComplete             = '2'
	CloseComplete            = '3'
	CommandComplete          = 'C'
	CopyData                 = 'd'
	CopyInResponse           = 'G'
	CopyOutResponse          = 'H'
	CopyBothResponse         = 'W'
	DataRow                  = 'D'
	EmptyQueryResponse       = 'I'
	ErrorResponse            = 'E'
	FunctionCallResponse     = 'V'
	NegotiateProtocolVersion = 'v'
	NoData                   = 'n'
	NoticeResponse           = 'N'
	NotificationResponse     = 'A'
	ParameterDescription     = 't'
	ParameterStatus          = 'S'
	ParseComplete            = '1'
	PortalSuspended          = 's'
	ReadyForQuery            = 'Z'
	RowDescription           = 'T'
)

const (
	// Specifies that the authentication was successful.
	AuthenticationOk = 0

	// Specifies that Kerberos V5 authentication is required.
	AuthenticationKerberosV5 = 2

	// Specifies that a clear-text password is required.
	AuthenticationCleartextPassword = 3

	// Specifies that an MD5-encrypted password is required.
	AuthenticationMD5Password = 5

	// Specifies that GSSAPI authentication is required.
	AuthenticationGSS = 7

	// Specifies that this message contains GSSAPI or SSPI data.
	AuthenticationGSSContinue = 8

	// Specifies that SSPI authentication is required.
	AuthenticationSSPI = 9

	// Specifies that SASL authentication is required.
	AuthenticationSASL = 10

	// Specifies that this message contains a SASL challenge.
	AuthenticationSASLContinue = 11

	// Specifies that SASL authentication has completed.
	AuthenticationSASLFinal = 12
)
