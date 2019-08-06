package awesomeProject

import (
	"fmt"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/mitchellh/mapstructure"
)

var (
	// these are our *global* config settings, to be shared by all packages.
	// each has corresponding public accessors below.
	// if anything requires a `Set` accessor, that indicates it perhaps
	// shouldn't be set here, because mutable vars shouldn't be global.
	clientID               string
	clientSecret           string
	tenantID               string
	subscriptionID         string
	locationDefault        string
	authorizationServerURL string
	cloudName              string = "AzurePublicCloud"
	useDeviceFlow          bool = false
	keepResources          bool
	groupName              string // deprecated, use baseGroupName instead
	baseGroupName          string
	userAgent              string
	environment            *azure.Environment
)

type AzureCredentials struct {
	ClientID       string  `mapstructure:"azure_client_id"`
	ClientSecret   string `mapstructure:"azure_client_secret"`
	TenantID       string `mapstructure:"azure_tenant_id"`
	SubscriptionID string `mapstructure:"azure_subscription_id"`
}

func NewAzureCredentials(params map[string]string) (AzureCredentials, error) {
	var creds AzureCredentials
	err := mapstructure.Decode(params, &creds)
	return creds, err
}

func SetConfiguration(creds AzureCredentials)  {
	clientID = creds.ClientID
	clientSecret = creds.ClientSecret
	tenantID = creds.TenantID
	subscriptionID = creds.SubscriptionID
}

// ClientID is the OAuth client ID.
func ClientID() string {
	return clientID
}

// ClientSecret is the OAuth client secret.
func ClientSecret() string {
	return clientSecret
}

// TenantID is the AAD tenant to which this client belongs.
func TenantID() string {
	return tenantID
}

// SubscriptionID is a target subscription for Azure resources.
func SubscriptionID() string {
	return subscriptionID
}

// SubscriptionID is a target subscription for Azure resources.
func SubscriptionID() string {
	return subscriptionID
}

// UseDeviceFlow() specifies if interactive auth should be used. Interactive
// auth uses the OAuth Device Flow grant type.
func UseDeviceFlow() bool {
	return useDeviceFlow
}

// AuthorizationServerURL is the OAuth authorization server URL.
// Q: Can this be gotten from the `azure.Environment` in `Environment()`?
func AuthorizationServerURL() string {
	return authorizationServerURL
}

// UserAgent() specifies a string to append to the agent identifier.
func UserAgent() string {
	if len(userAgent) > 0 {
		return userAgent
	}
	return "aurora-azure-sdk"
}

// Environment() returns an `azure.Environment{...}` for the current cloud.
func Environment() *azure.Environment {
	if environment != nil {
		return environment
	}
	env, err := azure.EnvironmentFromName(cloudName)
	if err != nil {
		// TODO: move to initialization of var
		panic(fmt.Sprintf(
			"invalid cloud name '%s' specified, cannot continue\n", cloudName))
	}
	environment = &env
	return environment
}

var (
	armAuthorizer      autorest.Authorizer
	batchAuthorizer    autorest.Authorizer
	graphAuthorizer    autorest.Authorizer
	keyvaultAuthorizer autorest.Authorizer
)

// OAuthGrantType specifies which grant type to use.
type OAuthGrantType int

const (
	// OAuthGrantTypeServicePrincipal for client credentials flow
	OAuthGrantTypeServicePrincipal OAuthGrantType = iota
	// OAuthGrantTypeDeviceFlow for device flow
	OAuthGrantTypeDeviceFlow
)

// GrantType returns what grant type has been configured.
func grantType() OAuthGrantType {
	if UseDeviceFlow() {
		return OAuthGrantTypeDeviceFlow
	}
	return OAuthGrantTypeServicePrincipal
}

// GetResourceManagementAuthorizer gets an OAuthTokenAuthorizer for Azure Resource Manager
func GetResourceManagementAuthorizer() (autorest.Authorizer, error) {
	if armAuthorizer != nil {
		return armAuthorizer, nil
	}

	var a autorest.Authorizer
	var err error

	a, err = getAuthorizerForResource(
		grantType(), Environment().ResourceManagerEndpoint)

	if err == nil {
		// cache
		armAuthorizer = a
	} else {
		// clear cache
		armAuthorizer = nil
	}
	return armAuthorizer, err
}
func getAuthorizerForResource(grantType OAuthGrantType, resource string) (autorest.Authorizer, error) {

	var a autorest.Authorizer
	var err error

	switch grantType {

	case OAuthGrantTypeServicePrincipal:
		oauthConfig, err := adal.NewOAuthConfig(
			Environment().ActiveDirectoryEndpoint, TenantID())
		if err != nil {
			return nil, err
		}

		token, err := adal.NewServicePrincipalToken(
			*oauthConfig, ClientID(), ClientSecret(), resource)
		if err != nil {
			return nil, err
		}
		a = autorest.NewBearerAuthorizer(token)

	case OAuthGrantTypeDeviceFlow:
		deviceconfig := auth.NewDeviceFlowConfig(ClientID(), TenantID())
		deviceconfig.Resource = resource
		a, err = deviceconfig.Authorizer()
		if err != nil {
			return nil, err
		}

	default:
		return a, fmt.Errorf("invalid grant type specified")
	}

	return a, err
}
func main() {

	params := map[string]string{
		"azure_client_id":       "",
		"azure_client_secret":   "",
		"azure_tenant_id":       "",
		"azure_subscription_id": "",
	}

	creds, err := NewAzureCredentials(params)
	if err != nil {
		fmt.Errorf("error=%s",err.Error())
	}
	SetConfiguration(creds)

	auth, _ := GetResourceManagementAuthorizer()
	if err != nil {
		fmt.Errorf("error=%s",err.Error())
	}
	fmt.Print(auth)

}
