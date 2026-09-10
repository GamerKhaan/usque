package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Diniboy1123/usque/models"
	"log"
	"net"
	"net/netip"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	SilenceUsage:  true,
	SilenceErrors: true,
	Use:           "register",
	Short:         "Register a new client and enroll a device key",
	Long: "Registers a new account and enrolls a device key. Also makes sure that it switches to" +
		" MASQUE mode. Saves the config to a file.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if config.ConfigLoaded {
			fmt.Printf("You already have a config. Do you want to overwrite it? (y/n) ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				return fmt.Errorf("failed to read response: %v", err)
			}
			if response != "y" {
				return nil
			}
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("failed to get config path: %v", err)
		}
		if configPath == "" {
			return fmt.Errorf("config path is required")
		}

		deviceName, err := cmd.Flags().GetString("name")
		if err != nil {
			return fmt.Errorf("failed to get device name: %v", err)
		}

		locale, err := cmd.Flags().GetString("locale")
		if err != nil {
			return fmt.Errorf("failed to get locale: %v", err)
		}

		model, err := cmd.Flags().GetString("model")
		if err != nil {
			return fmt.Errorf("failed to get model: %v", err)
		}

		jwt, err := cmd.Flags().GetString("jwt")
		if err != nil {
			return fmt.Errorf("failed to get jwt: %v", err)
		}

		if jwt != "" {
			log.Printf("Registering with locale %s and model %s using jwt authentication", locale, model)
		} else {
			log.Printf("Registering with locale %s and model %s", locale, model)
		}

		acceptTos, err := cmd.Flags().GetBool("accept-tos")
		if err != nil {
			return fmt.Errorf("failed to get accept-tos flag: %v", err)
		}

		accountData, err := api.Register(model, locale, jwt, acceptTos)
		if err != nil {
			return registrationFailure("register", err)
		}

		if accountData == nil || accountData.ID == "" || accountData.Token == "" {
			return fmt.Errorf("registration returned incomplete device credentials")
		}
		privKey, pubKey, err := internal.GenerateEcKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate key pair: %v", err)
		}

		log.Printf("Enrolling device key...")

		updatedAccountData, err := api.EnrollKey(accountData.ID, accountData.Token, pubKey, deviceName)
		if err != nil {
			return registrationFailure("enroll", err)
		}

		log.Printf("Successful registration. Saving config...")

		registeredConfig, err := registrationConfig(updatedAccountData, accountData.Token, privKey)
		if err != nil {
			return err
		}
		config.AppConfig = registeredConfig
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			return fmt.Errorf("failed to save config: %v", err)
		}

		log.Printf("Config saved to %s", configPath)
		return nil
	},
}

func init() {
	registerCmd.Flags().StringP("locale", "l", internal.DefaultLocale, "locale")
	registerCmd.Flags().StringP("model", "m", internal.DefaultModel, "model")
	registerCmd.Flags().StringP("name", "n", "", "device name")
	registerCmd.Flags().String("jwt", "", "team token")
	registerCmd.Flags().BoolP("accept-tos", "a", false, "accept Cloudflare TOS (not interactive setup)")
	rootCmd.AddCommand(registerCmd)
}

// Never relay a remote API error message that could echo credential material.
func registrationFailure(phase string, err error) error {
	var apiErr *models.APIError
	if errors.As(err, &apiErr) {
		codes := make([]int, 0, len(apiErr.Errors))
		for _, e := range apiErr.Errors {
			codes = append(codes, e.Code)
		}
		return fmt.Errorf("WARP %s failed (API codes %v); check reachability and retry usquectl register", phase, codes)
	}
	return fmt.Errorf("WARP %s failed; check network, DNS, clock and Cloudflare availability, then retry usquectl register", phase)
}

func registrationConfig(account *models.AccountData, token string, privateKey []byte) (config.Config, error) {
	var result config.Config
	if account == nil || len(account.Config.Peers) == 0 {
		return result, fmt.Errorf("enrollment response contains no peers")
	}
	peer := account.Config.Peers[0]
	parseEndpoint := func(value string, ipv4 bool) (string, error) {
		host, _, err := net.SplitHostPort(value)
		if err != nil {
			return "", fmt.Errorf("enrollment returned an invalid endpoint")
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Is4() != ipv4 {
			return "", fmt.Errorf("enrollment returned an invalid endpoint address")
		}
		return addr.String(), nil
	}
	v4, err := parseEndpoint(peer.Endpoint.V4, true)
	if err != nil {
		return result, err
	}
	v6, err := parseEndpoint(peer.Endpoint.V6, false)
	if err != nil {
		return result, err
	}
	result = config.Config{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		EndpointV4: v4, EndpointV6: v6,
		EndpointH2V4: config.DefaultEndpointH2V4, EndpointH2V6: config.DefaultEndpointH2V6,
		EndpointPubKey: peer.PublicKey, ID: account.ID, AccessToken: token,
		IPv4: account.Config.Interface.Addresses.V4, IPv6: account.Config.Interface.Addresses.V6,
	}
	if err := result.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("incomplete enrollment configuration: %w", err)
	}
	return result, nil
}
