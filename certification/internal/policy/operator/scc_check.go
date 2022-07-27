package operator

import (
	"context"
	"fmt"
	"os"

	"github.com/redhat-openshift-ecosystem/openshift-preflight/certification/internal/bundle"
	log "github.com/sirupsen/logrus"

	"github.com/redhat-openshift-ecosystem/openshift-preflight/certification"
)

// SecurityContextConstraintsCheck evaluates the csv and logs a message if a non default security context constraint is
// needed by the operator

type SecurityContextConstraintsCheck struct {
	customSCCSpecified  bool
	builtInSCCSpecified bool
}

func getDefaultSCCs() []string {
	return []string{"restricted", "privileged", "nonroot", "hostnetwork", "hostmount-anyuid", "hostaccess", "anyuid"}
}

func NewSecurityContextConstraintsCheck() *SecurityContextConstraintsCheck {
	return &SecurityContextConstraintsCheck{
		false,
		false,
	}
}

func (p *SecurityContextConstraintsCheck) Validate(ctx context.Context, bundleRef certification.ImageReference) (bool, error) {
	requestedSCCList, err := p.dataToValidate(ctx, bundleRef.ImageFSPath)
	if err != nil {
		return false, err
	}

	return p.validate(ctx, requestedSCCList)
}

func (p *SecurityContextConstraintsCheck) dataToValidate(ctx context.Context, imagePath string) ([]string, error) {
	csvFilepath, err := bundle.GetCsvFilePathFromBundle(imagePath)
	if err != nil {
		return nil, err
	}

	csvFileReader, err := os.Open(csvFilepath)
	if err != nil {
		return nil, err
	}

	requestedSccList, err := bundle.GetSecurityContextConstraints(ctx, csvFileReader)
	if err != nil {
		return nil, fmt.Errorf("unable to extract security context constraints from ClusterServiceVersion: %w", err)
	}

	return requestedSccList, nil
}

func (p *SecurityContextConstraintsCheck) validate(ctx context.Context, requestedSccList []string) (bool, error) {
	defaultSccList := getDefaultSCCs()

	if requestedSccList == nil || len(requestedSccList) == 0 {
		log.Infof("No security context constraint was requested so using the default %s scc", defaultSccList[0])
		return true, nil
	}

	if len(requestedSccList) != 1 {
		return false, fmt.Errorf("only one scc should be requested at a time")
	}

	for _, defaultScc := range defaultSccList {
		if requestedSccList[0] == defaultScc {
			log.Infof("A built in default security context constraint %s was requested", defaultScc)
			p.builtInSCCSpecified = true
			return true, nil
		}
	}

	log.Infof("A custom scc was specified: %s", requestedSccList[0])
	p.customSCCSpecified = true
	return true, nil
}

func (p *SecurityContextConstraintsCheck) Name() string {
	return "SecurityContextConstraintsCheck"
}

func (p *SecurityContextConstraintsCheck) Metadata() certification.Metadata {
	return certification.Metadata{
		Description:      "Evaluates the csv and logs a message if a non default security context constraint is needed by the operator",
		Level:            "optional",
		KnowledgeBaseURL: "https://redhat-connect.gitbook.io/certified-operator-guide/troubleshooting-and-resources/sccs", // Placeholder
		CheckURL:         "https://redhat-connect.gitbook.io/certified-operator-guide/troubleshooting-and-resources/sccs", // Placeholder
	}
}

func (p *SecurityContextConstraintsCheck) Help() certification.HelpText {
	if p.customSCCSpecified {
		return certification.HelpText{
			Message: "A custom security context constraint was detected in the csv. " +
				"Please see the operators documentation for details.",
			Suggestion: "A custom security context constraint may need to be applied by a cluster admin.",
		}
	}

	if p.builtInSCCSpecified {
		return certification.HelpText{
			Message: "A built in default security context constraint was detected in the csv. " +
				"Please see the operators documentation for details.",
			Suggestion: "No action needed.",
		}
	}

	return certification.HelpText{
		Message: "The SecurityContextConstraintsCheck logs a message if the operator requests a " +
			"security context constraint. Please review the operators documentation to see if this is needed.",
		Suggestion: "Check if the operator requests a security context constraint in its csv",
	}
}

