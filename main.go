package main

import (
	"fmt"
	"os"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/gopengraph"
)

var (
	// Configuration
	useLdaps   bool
	debug      bool
	outputFile string

	// Network settings
	domainController string
	ldapPort         int

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	useKerberos  bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "KeyCredentialHound - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0"}

	// Configuration flags
	ap.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
	ap.NewStringArgument(&outputFile, "-o", "--output-file", "", false, "Output file name.")

	group_ldapSettings, err := ap.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		group_ldapSettings.NewTcpPortArgument(&ldapPort, "-P", "--port", 389, false, "Port number to connect to LDAP server.")
		group_ldapSettings.NewBoolArgument(&useLdaps, "-l", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}

	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--username", "", false, "User to authenticate as.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()

	if useLdaps && !group_ldapSettings.LongNameToArgument["--port"].IsPresent() {
		ldapPort = 636
	}
}

func main() {
	parseArgs()

	if len(outputFile) == 0 {
		outputFile = fmt.Sprintf("%s_keycredentials.json", time.Now().Format("20060102150405"))
	}

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials: %s", err))
		return
	}

	// Parsing input values for Distinguished Name
	if debug {
		if !useLdaps {
			logger.Debug(fmt.Sprintf("Connecting to remote ldap://%s:%d ...", domainController, ldapPort))
		} else {
			logger.Debug(fmt.Sprintf("Connecting to remote ldaps://%s:%d ...", domainController, ldapPort))
		}
	}

	ldapSession, err := ldap.NewSession(domainController, ldapPort, creds, useLdaps, useKerberos)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating LDAP session: %s", err))
		return
	}
	success, err := ldapSession.Connect()
	if err != nil {
		logger.Warn(fmt.Sprintf("Error connecting to LDAP: %s", err))
		return
	}

	if success {
		logger.Info(fmt.Sprintf("Connected as '%s\\%s'", authDomain, authUsername))

		query := "(msDS-KeyCredentialLink=*)"
		if debug {
			logger.Debug(fmt.Sprintf("LDAP query used: %s", query))
		}
		attributes := []string{"distinguishedName", "msDS-KeyCredentialLink", "objectSid"}
		ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error querying LDAP: %s", err))
			return
		}

		og := gopengraph.NewOpenGraph("KeyCredentialBase")

		ParseResults(ldapResults, og, debug)

		logger.Info(fmt.Sprintf("Exporting graph to file: %s", outputFile))
		jsonData, err := og.ExportJSON(false)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error exporting graph to file: %s", err))
			return
		}
		err = os.WriteFile(outputFile, []byte(jsonData), 0600)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error exporting graph to file: %s", err))
			return
		}
		logger.Info(fmt.Sprintf("Graph exported to file: %s", outputFile))

	} else {
		if debug {
			logger.Warn("Error: Could not create ldapSession.")
		}
	}
}
