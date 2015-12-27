package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	etcd "github.com/coreos/etcd/client"
	vault "github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

var (
	username   string
	password   string
	listenAddr string
	tlsCert    string
	tlsKey     string
	etcdAddr   string
	vaultAddr  string
	vaultToken string
)

var (
	defaultEtcdAddr   = "http://127.0.0.1:2379"
	defaultVaultAddr  = "http://127.0.0.1:8200"
	defaultListenAddr = "127.0.0.1:443"
	defaultTLSCert    = "/etc/app/ssl/cert.pem"
	defaultTLSKey     = "/etc/app/ssl/key.pem"
)

var configKeys = []string{
	"username",
	"password",
	"listen_addr",
	"tls_cert",
	"tls_key",
	"etcd_addr",
	"vault_addr",
	"vault_token",
}

func init() {
	flag.StringVar(&username, "username", "", "Username.")
	flag.StringVar(&password, "password", "", "Password.")
	flag.StringVar(&listenAddr, "listen-addr", defaultListenAddr, "Listen address.")
	flag.StringVar(&tlsCert, "tls-cert", defaultTLSCert, "TSL server cert.")
	flag.StringVar(&tlsKey, "tls-key", defaultTLSKey, "TSL server key.")
	flag.StringVar(&etcdAddr, "etcd-addr", defaultEtcdAddr, "etcd address.")
	flag.StringVar(&vaultAddr, "vault-addr", defaultVaultAddr, "vault address.")
	flag.StringVar(&vaultToken, "vault-token", "", "vault token.")
}

type Config struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	ListenAddr string `json:"listen_addr"`
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`
	EtcdAddr   string `json:"etcd_addr"`
	VaultAddr  string `json:"vault_addr"`
	VaultToken string `json:"vault_token"`
}

func ConfigFromFile(path string) (Config, error) {
	c := Config{}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		log.Println("config file does not exist")
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return c, err
	}
	return c, nil
}

func ConfigFromEnv() Config {
	return Config{
		Username:   os.Getenv("APP_USERNAME"),
		Password:   os.Getenv("APP_PASSWORD"),
		ListenAddr: os.Getenv("APP_LISTEN_ADDR"),
		TLSCert:    os.Getenv("APP_TLS_CERT"),
		TLSKey:     os.Getenv("APP_TLS_KEY"),
		EtcdAddr:   os.Getenv("APP_ETCD_ADDR"),
		VaultAddr:  os.Getenv("APP_VAULT_ADDR"),
		VaultToken: os.Getenv("APP_VAULT_TOKEN"),
	}
}

func ConfigFromFlags() Config {
	return Config{
		Username:   username,
		Password:   password,
		ListenAddr: listenAddr,
		TLSCert:    tlsCert,
		TLSKey:     tlsKey,
		EtcdAddr:   etcdAddr,
		VaultAddr:  vaultAddr,
		VaultToken: vaultToken,
	}
}

func ConfigFromEtcd(addr string) (Config, error) {
	c := Config{}

	cfg := etcd.Config{
		Endpoints:               []string{addr},
		Transport:               etcd.DefaultTransport,
		HeaderTimeoutPerRequest: time.Second,
	}
	client, err := etcd.New(cfg)
	if err != nil {
		return c, err
	}
	kapi := etcd.NewKeysAPI(client)

	return walk(configKeys, func(key string) (string, error) {
		key = fmt.Sprintf("/app/%s", key)
		resp, err := kapi.Get(context.Background(), key, nil)
		if isKeyNotExist(err) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return resp.Node.Value, nil
	})
}

func ConfigFromVault(addr, token string) (Config, error) {
	var c Config
	vfg := vault.DefaultConfig()
	vfg.Address = addr

	vc, err := vault.NewClient(vfg)
	if err != nil {
		return c, err
	}
	vc.SetToken(token)

	return walk(configKeys, func(key string) (string, error) {
		key = fmt.Sprintf("secret/%s", key)
		secret, err := vc.Logical().Read(key)
		if err != nil {
			return "", err
		}
		if secret != nil {
			return secret.Data["value"].(string), nil
		}
		return "", nil
	})
}

func walk(keys []string, walkFn WalkFunc) (Config, error) {
	c := Config{}
	for _, key := range keys {
		value, err := walkFn(key)
		if err != nil {
			return c, err
		}
		switch key {
		case "username":
			c.Username = value
		case "password":
			c.Password = value
		case "listenaddr":
			c.ListenAddr = value
		case "tlscert":
			c.TLSCert = value
		case "tlskey":
			c.TLSKey = value
		}
	}
	return c, nil
}

type WalkFunc func(key string) (string, error)

func isKeyNotExist(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), "100: Key not found")
}

func NewConfig() *Config {
	return &Config{
		ListenAddr: defaultListenAddr,
		TLSCert:    defaultTLSCert,
		TLSKey:     defaultTLSKey,
	}
}

func (c *Config) Override(src Config) {
	if src.Username != "" {
		c.Username = src.Username
	}
	if src.Password != "" {
		c.Password = src.Password
	}
	if src.ListenAddr != "" {
		c.ListenAddr = src.ListenAddr
	}
	if src.TLSCert != "" {
		c.TLSCert = src.TLSCert
	}
	if src.TLSKey != "" {
		c.TLSKey = src.TLSKey
	}
	if src.EtcdAddr != "" {
		c.EtcdAddr = src.EtcdAddr
	}
	if src.VaultAddr != "" {
		c.VaultAddr = src.VaultAddr
	}
	if src.VaultToken != "" {
		c.VaultToken = src.VaultToken
	}
}

var configTemplate = `    Username: %s
    Password: %s
  ListenAddr: %s
     TLSCert: %s
      TLSKey: %s
    EtcdAddr: %s
   VaultAddr: %s`

func (c *Config) String() string {
	return fmt.Sprintf(configTemplate, c.Username, c.Password, c.ListenAddr, c.TLSCert, c.TLSKey, c.EtcdAddr, c.VaultAddr)
}
