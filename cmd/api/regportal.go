package main

import (
	"time"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/regportal"
)

// portalConfig is the portal's configuration from the environment.
func portalConfig(cfg *config.API) regportal.Config {
	s := func(n int) time.Duration { return time.Duration(n) * time.Second }
	return regportal.Config{
		Applications: cfg.RegistryApplications == "on", OperatorReports: cfg.RegistryOperatorReports == "on",
		PortalURL: cfg.RegistryPortalURL, VerifyTTL: s(cfg.RegistryApplicationVerifyTTLS), Retain: s(cfg.RegistryApplicationsRetainS),
		Validity: s(cfg.RegistryApplicationValidityS), ApplicationsIP: cfg.RegistryApplicationsPerIP, Window: s(cfg.RegistryApplicationsWindowS),
		IssuePrefix: cfg.RegistryIssuePrefix, IssueRandomLen: cfg.RegistryIssueRandomLen, LinkTTL: s(cfg.RegistryOperatorLinkTTLS),
		LinksIP: cfg.RegistryOperatorLinksPerIP, LinksOperator: cfg.RegistryOperatorLinksPerOwner, MailBatch: cfg.RegistryMailBatch,
		MailMaxAttempts: cfg.RegistryMailMaxAttempts, MailRetry: s(cfg.RegistryMailRetryS), MailTimeout: s(cfg.RegistryMailTimeoutS),
	}
}
