package commercetools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/command/agent/cache"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

const policyAdmin = `
path "*" {
	capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}
`

func TestVaultClusterUp(t *testing.T) {
	logger := logging.NewVaultLogger(hclog.Trace)
	coreConfig := &vault.CoreConfig{
		Logger: logger,
		LogicalBackends: map[string]logical.Factory{
			"kv": vault.LeasedPassthroughBackendFactory,
		},
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t,
		coreConfig,
		&vault.TestClusterOptions{
			HandlerFunc: vaulthttp.Handler,
		})
	cluster.Start()
	defer cluster.Cleanup()

	t.Run("vault_health_200", func(t *testing.T) {
		vault.TestWaitActive(t, cluster.Cores[0].Core)
		serverClient := cluster.Cores[0].Client
		req := serverClient.NewRequest("HEAD", "/v1/sys/health")
		request(t, serverClient, req, 200)
		//TODO: two proxy clients, credential, secrets backend.
	})

	t.Run("get_auth_token", func(t *testing.T) {
		// clienToUse is the client for the agent to point to.
		// testClient is the client that is used to talk to the agent for proxying/caching behavior.

		cleanup, _, testClient, leaseCache := setupClusterAndAgentCommon(context.TODO(), t, coreConfig, false)
		defer cleanup()

		sampleSpace := make(map[string]string)
		token1 := testClient.Token()
		sampleSpace[token1] = "token"

		// Mount the kv backend
		err := testClient.Sys().Mount("kv", &api.MountInput{
			Type: "kv",
		})
		if err != nil {
			t.Fatal(err)
		}

		// Create a secret in the backend
		_, err = testClient.Logical().Write("kv/foo", map[string]interface{}{
			"value": "bar",
			"ttl":   "5",
		})
		if err != nil {
			t.Fatal(err)
		}

		// Read the secret and create a lease
		leaseResp, err := testClient.Logical().Read("kv/foo")
		if err != nil {
			t.Fatal(err)
		}
		lease1 := leaseResp.LeaseID
		sampleSpace[lease1] = "lease"
		time.Sleep(15 * time.Second)
		// Second lease call
		leaseResp, err = testClient.Logical().Read("kv/foo")
		if err != nil {
			t.Fatal(err)
		}
		lease2 := leaseResp.LeaseID
		sampleSpace[lease2] = "lease"

		_ = struct {
			x interface{}
		}{
			x: leaseCache,
		}

	})

}

// request issues HTTP requests.
func request(t *testing.T, client *api.Client, req *api.Request, expectedStatusCode int) map[string]interface{} {
	t.Helper()
	resp, err := client.RawRequest(req)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if resp.StatusCode != expectedStatusCode {
		t.Fatalf("expected status code %d, not %d", expectedStatusCode, resp.StatusCode)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if len(bytes) == 0 {
		return nil
	}

	var body map[string]interface{}
	err = json.Unmarshal(bytes, &body)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return body
}

func setupClusterAndAgentCommon(ctx context.Context, t *testing.T, coreConfig *vault.CoreConfig, onStandby bool) (func(), *api.Client, *api.Client, *cache.LeaseCache) {
	t.Helper()

	if ctx == nil {
		ctx = context.Background()
	}

	// Handle sane defaults
	if coreConfig == nil {
		coreConfig = &vault.CoreConfig{
			DisableMlock: true,
			DisableCache: true,
			Logger:       logging.NewVaultLogger(hclog.Trace),
		}
	}

	// Always set up the userpass backend since we use that to generate an admin
	// token for the client that will make proxied requests to through the agent.
	if coreConfig.CredentialBackends == nil || coreConfig.CredentialBackends["userpass"] == nil {
		coreConfig.CredentialBackends = map[string]logical.Factory{
			"userpass": userpass.Factory,
		}
	}

	// Init new test cluster
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)

	activeClient := cores[0].Client
	standbyClient := cores[1].Client

	// clienToUse is the client for the agent to point to.
	clienToUse := activeClient
	if onStandby {
		clienToUse = standbyClient
	}

	// Add an admin policy
	if err := activeClient.Sys().PutPolicy("admin", policyAdmin); err != nil {
		t.Fatal(err)
	}

	// Set up the userpass auth backend and an admin user. Used for getting a token
	// for the agent later down in this func.
	err := activeClient.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = activeClient.Logical().Write("auth/userpass/users/foo", map[string]interface{}{
		"password":      "bar",
		"policies":      []string{"admin"},
		"token_ttl":     "1h",
		"token_max_ttl": "1h",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set up env vars for agent consumption
	origEnvVaultAddress := os.Getenv(api.EnvVaultAddress)
	os.Setenv(api.EnvVaultAddress, clienToUse.Address())

	origEnvVaultCACert := os.Getenv(api.EnvVaultCACert)
	os.Setenv(api.EnvVaultCACert, fmt.Sprintf("%s/ca_cert.pem", cluster.TempDir))

	// cacheLogger := vault.NewTestLogger(t)

	// cacheLogger.SetLevel(hclog.Debug)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	cacheLogger := logging.NewVaultLogger(hclog.Trace).Named("cache")
	// Create the API proxier
	apiProxy, err := cache.NewAPIProxy(&cache.APIProxyConfig{
		Client: clienToUse,
		Logger: cacheLogger.Named("apiproxy"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create the lease cache proxier and set its underlying proxier to
	// the API proxier.
	leaseCache, err := cache.NewLeaseCache(&cache.LeaseCacheConfig{
		Client:      clienToUse,
		BaseContext: ctx,
		Proxier:     apiProxy,
		Logger:      cacheLogger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a muxer and add paths relevant for the lease cache layer
	mux := http.NewServeMux()
	mux.Handle("/agent/v1/cache-clear", leaseCache.HandleCacheClear(ctx))

	mux.Handle("/", cache.Handler(ctx, cacheLogger, leaseCache, nil, true))
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          cacheLogger.StandardLogger(nil),
	}
	go server.Serve(listener)

	// testClient is the client that is used to talk to the agent for proxying/caching behavior.
	testClient, err := activeClient.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if err := testClient.SetAddress("http://" + listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	// Login via userpass method to derive a managed token. Set that token as the
	// testClient's token
	resp, err := testClient.Logical().Write("auth/userpass/login/foo", map[string]interface{}{
		"password": "bar",
	})
	if err != nil {
		t.Fatal(err)
	}
	testClient.SetToken(resp.Auth.ClientToken)

	cleanup := func() {
		// We wait for a tiny bit for things such as agent renewal to exit properly
		time.Sleep(50 * time.Millisecond)

		cluster.Cleanup()
		os.Setenv(api.EnvVaultAddress, origEnvVaultAddress)
		os.Setenv(api.EnvVaultCACert, origEnvVaultCACert)
		listener.Close()
	}

	return cleanup, clienToUse, testClient, leaseCache
}

func TestVault(t *testing.T) {
	logger := logging.NewVaultLogger(hclog.Debug).Named("testvault")
	cluster := vault.NewTestCluster(t,
		&vault.CoreConfig{},
		&vault.TestClusterOptions{
			Logger:      logger,
			HandlerFunc: vaulthttp.Handler,
		})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	resp, err := client.Logical().Read("/auth/token/lookup-self")
	if err != nil {
		t.Error(err)
	}
	_ = resp

	// Enable approle auth method
	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add policy
	// Add an kv read policy
	policy := `
	path "secret/data/test-secret" {
		capabilities = [ "read" ]
		}

	path "auth/token/lookup-self" {
			capabilities = ["read"]
		}

	path "auth/token/renew-self" {
			capabilities = ["update", "create"]
		}
		`
	if err := client.Sys().PutPolicy("kv-policy", policy); err != nil {
		t.Fatal(err)
	}

	//establish the test-role with "kv-policy"
	_, err = client.Logical().Write("auth/approle/role/test-role", map[string]interface{}{
		"token_ttl":      "5",
		"token_max_ttl":  "10",
		"token_policies": []string{"kv-policy"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("secret/data/test-secret", map[string]interface{}{
		"SecretKey": "SecretValue",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get RoleId
	resp, err = client.Logical().Read("auth/approle/role/test-role/role-id")
	if err != nil {
		t.Fatal(err)
	}
	roleID := resp.Data["role_id"].(string)
	_ = roleID
	// Get SecretId
	resp, err = client.Logical().Write("auth/approle/role/test-role/secret-id", make(map[string]interface{}))
	if err != nil {
		t.Fatal(err)
	}
	secretID := resp.Data["secret_id"].(string)
	_ = secretID

	// Login

	// Create new client using appRole token
	clientAppRole, err := client.Clone()
	if err != nil {
		t.Fatal(err)
	}
	clientAppRole.ClearToken()

	resp, err = clientAppRole.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for login")
	}
	if resp.Auth == nil {
		t.Fatal("expected auth object from response")
	}
	if resp.Auth.ClientToken == "" {
		t.Fatal("expected a client token")
	}
	clientToken := resp.Auth.ClientToken
	clientAppRole.SetToken(clientToken)

	// Renew token
	resp, err = clientAppRole.Logical().Write("auth/token/renew-self", map[string]interface{}{})
	_ = resp

	if err != nil {
		t.Fatal("could not renew", err)
	}
	t.Log(">>>>>>>>>>>>>>>>>>>>>Renewed token", err)
	// Create the API proxier
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// Create the lease cache proxier and set its underlying proxier to
	// the API proxier.

	// Create the API proxier
	apiProxy, err := cache.NewAPIProxy(&cache.APIProxyConfig{
		Client: clientAppRole,
		Logger: logger.Named("proxy"),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	leaselogger := logger.Named("leasecache")

	leaseCache, err := cache.NewLeaseCache(&cache.LeaseCacheConfig{
		Client:      clientAppRole,
		BaseContext: ctx,
		Proxier:     apiProxy,
		Logger:      leaselogger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a muxer and add paths relevant for the lease cache layer
	mux := http.NewServeMux()
	mux.Handle("/agent/v1/cache-clear", leaseCache.HandleCacheClear(ctx))

	mux.Handle("/", cache.Handler(ctx, leaselogger, leaseCache, nil, true))
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          logger.StandardLogger(nil),
	}
	go server.Serve(listener)

	if err := clientAppRole.SetAddress("http://" + listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	//TODO: have three clients; root, cache/proxy (with address of server), approle(with address of cache/proxy)
	// Login
	activeClient, err := clientAppRole.Clone()
	if err != nil {
		t.Fatal(err)
	}
	resp, err = activeClient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	_ = resp
	activeClient.SetToken(resp.Auth.ClientToken)

	time.Sleep(11 * time.Second)

	resp, err = activeClient.Logical().Write("auth/token/renew-self", map[string]interface{}{})
	if err != nil {
		t.Error("#452 failed to renew:", err)
	}
	_ = resp

	resp, err = activeClient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	_ = resp
	// // Create a named role
	// req = serverClient.NewRequest("PUT", "/v1/auth/approle/role/test-role")
	// req.BodyBytes = []byte(`{
	// 	  "token_ttl": "5m",
	// 		"token_policies":"default,myapp-read",
	// 		"policies":"default,myapp-read"
	// 	}`)
	// request(t, serverClient, req, 204)
	t.Log(">>>>>>>>>>>>>>>>>>>>>>>>>>>>bottom")

}

// newLeaseCacheProxier starts a proxied lease cache server
// and returns the address
func newLeaseCacheProxier(client *api.Client, count string) string {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")

	// Create the API proxier
	cacheLogger := logging.NewVaultLogger(hclog.Trace).Named(fmt.Sprintf("leaseCache%s", count))
	proxy, _ := cache.NewAPIProxy(&cache.APIProxyConfig{
		Client: client,
		Logger: cacheLogger.Named("apiproxy"),
	})

	// Create the lease cache proxier and set its underlying proxier to
	// the API proxier.
	ctx := context.Background()
	leaseCache, _ := cache.NewLeaseCache(&cache.LeaseCacheConfig{
		Client:      client,
		BaseContext: ctx,
		Proxier:     proxy,
		Logger:      cacheLogger.Named("leasecache"),
	})

	// Create a muxer and add paths relevant for the lease cache layer
	mux := http.NewServeMux()
	mux.Handle(consts.AgentPathCacheClear, leaseCache.HandleCacheClear(ctx))

	// Passing a non-nil inmemsink tells the agent to use the auto-auth token
	cacheHandler := cache.Handler(ctx, cacheLogger, leaseCache, nil, true)
	mux.Handle("/", cacheHandler)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 100 * time.Second,
		ReadTimeout:       300 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          cacheLogger.StandardLogger(nil),
	}

	go server.Serve(listener)
	return listener.Addr().String()
}

func setupVaultCluster(t *testing.T, coreConfig *vault.CoreConfig) *vault.TestCluster {
	t.Helper()
	vaultLogger := logging.NewVaultLogger(hclog.Trace).Named("vault")

	// Handle sane defaults
	if coreConfig == nil {
		coreConfig = &vault.CoreConfig{
			DisableMlock: true,
			DisableCache: true,
			Logger:       vaultLogger,
		}
	}

	// Always set up the userpass backend since we use that to generate an admin
	// token for the client that will make proxied requests to through the agent.
	if coreConfig.CredentialBackends == nil || coreConfig.CredentialBackends["userpass"] == nil {
		coreConfig.CredentialBackends = map[string]logical.Factory{
			"userpass": userpass.Factory,
		}
	}

	// Init new test cluster
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	vault.TestWaitActive(t, cluster.Cores[0].Core)
	return cluster
}

func TestVaultAndProxyAgents(t *testing.T) {
	logger := logging.NewVaultLogger(hclog.Trace)
	logger.Trace("ARTHUR SAYS HI")

	cluster, roleID, secretID := setupVaultClusterWithApprole(t)
	clusterClient := cluster.Cores[0].Client
	clusterClient.ClearToken() //clear token so that we're sure not be using the admin token

	proxyAddr1 := newLeaseCacheProxier(clusterClient, "1")

	testClient, _ := clusterClient.Clone()

	if err := testClient.SetAddress("http://" + proxyAddr1); err != nil {
		t.Fatal(err)
	}

	respSecret, err := testClient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if respSecret == nil {
		t.Fatal("expected a response for login")
	}
	if respSecret.Auth == nil {
		t.Fatal("expected auth object from response")
	}
	if respSecret.Auth.ClientToken == "" {
		t.Fatal("expected a client token")
	}

	testClient.SetToken(respSecret.Auth.ClientToken)

	secret1, err := testClient.Logical().Write("auth/token/renew-self", map[string]interface{}{})
	if err != nil {
		t.Error("Failed renew-self", err)
		t.Fatal()
	}

	logger.Trace("TOKEN LeaseDuration1=", secret1.Auth.LeaseDuration)
	logger.Trace("SLEEPING TO AGE CREDENTIAL IN CACHE 1")
	time.Sleep(15 * time.Second)

	proxyAddr2 := newLeaseCacheProxier(testClient, "2")
	testClient2, _ := clusterClient.Clone()
	if err := testClient2.SetAddress("http://" + proxyAddr2); err != nil {
		t.Fatal(err)
	}
	testClient2.SetToken(respSecret.Auth.ClientToken)
	testClient1 := testClient
	testClient = testClient2
	secret2, err := testClient.Logical().Write("auth/token/renew-self", map[string]interface{}{})
	if err != nil {
		t.Error("Failed renew-self", fmt.Sprintf("%+v", testClient.Token()), err)
	}
	logger.Trace("TOKEN LeaseDuration2=", secret2.Auth.LeaseDuration)
	secret1, _ = testClient1.Auth().Token().LookupSelf()
	logger.Trace("TOKEN LeaseDuration1=", secret1.Data["ttl"])

	time.Sleep(1 * time.Second)
	_, err = testClient.Logical().Write("auth/token/renew-self", map[string]interface{}{})
	if err != nil {
		t.Error("Failed renew-self", fmt.Sprintf("%+v", testClient.Token()), err)
	}
	logger.Trace("GOODBYE")
	t.Fatal()

	respSecret, err = testClient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if respSecret == nil {
		t.Fatal("expected a response for login")
	}
	if respSecret.Auth == nil {
		t.Fatal("expected auth object from response")
	}
	if respSecret.Auth.ClientToken == "" {
		t.Fatal("expected a client token")
	}

	// AT THIS POINT CACHE 2 HAS A CAHCED CREDENTIAL WITH A TTL OF 10?
	time.Sleep(10 * time.Second)
	t.Fatal()

	logger.Trace(fmt.Sprintf("%#v", respSecret.Auth))
	testClient.SetToken(respSecret.Auth.ClientToken)
	logger.Trace(testClient.Token())

	//time.Sleep(5 * time.Second)

	logger.Trace(fmt.Sprintf("CALL APPROLE LOGIN AFTER SLEEP"))
	respSecret, err = testClient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if respSecret == nil {
		t.Fatal("expected a response for login")
	}
	if respSecret.Auth == nil {
		t.Fatal("expected auth object from response")
	}
	if respSecret.Auth.ClientToken == "" {
		t.Fatal("expected a client token")
	}
	// logger.Trace("*********TRIGGER RENEW")
	// respSecret, err = testClient.Logical().Write("auth/token/renew-self", map[string]interface{}{})
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// if respSecret == nil {
	// 	t.Fatal("expected a response for login")
	// }
	// if respSecret.Auth == nil {
	// 	t.Fatal("expected auth object from response")
	// }
	// if respSecret.Auth.ClientToken == "" {
	// 	t.Fatal("expected a client token")
	// }
	// time.Sleep(30 * time.Second)
}

// Setup Vault Server with AppRole backend.
// TODO: and add approle credentials.
// TODO: bindSecret, true or false?
func setupVaultClusterWithApprole(t *testing.T) (*vault.TestCluster, string, string) {
	t.Helper()
	vaultLogger := logging.NewVaultLogger(hclog.Trace).Named("vault")

	// Handle sane defaults

	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       vaultLogger,
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}

	clusters := setupVaultCluster(t, coreConfig)
	client := clusters.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := `
	path "auth/token/lookup-self" {
		capabilities = ["read"]
	}

	path "auth/token/renew-self" {
		capabilities = ["update", "create"]
	}
	`
	if err := client.Sys().PutPolicy("renewSelfAllow", policy); err != nil {
		t.Fatal(err)
	}

	//establish the test-role with "renewSelfAllow"
	_, err = client.Logical().Write("auth/approle/role/test-role", map[string]interface{}{
		"token_ttl":     "18",
		"token_max_ttl": "18",
		// "token_policies": []string{"renewSelfAllow"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get RoleId
	resp, err := client.Logical().Read("auth/approle/role/test-role/role-id")
	if err != nil {
		t.Fatal(err)
	}
	roleID := resp.Data["role_id"].(string)

	// Get SecretId
	resp, err = client.Logical().Write("auth/approle/role/test-role/secret-id", make(map[string]interface{}))
	if err != nil {
		t.Fatal(err)
	}
	secretID := resp.Data["secret_id"].(string)

	return clusters, roleID, secretID
}
