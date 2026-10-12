# Convenience targets for the YubiVault IaC.
#
# One-time platform setup and the repeatable PKI rotation. Both work with
# OpenTofu (tofu) or Terraform (terraform); set TF to switch.
#
#   make platform-apply
#   make pki-plan
#   make rotate-rekey
#   make rotate-recreate

TF ?= tofu

.PHONY: fmt validate platform-init platform-plan platform-apply \
        pki-init pki-plan pki-apply rotate-rekey rotate-recreate

fmt:
	$(TF) -chdir=platform fmt
	$(TF) -chdir=pki fmt

validate:
	$(TF) -chdir=platform validate
	$(TF) -chdir=pki validate

platform-init:
	$(TF) -chdir=platform init

platform-plan:
	$(TF) -chdir=platform plan

platform-apply:
	$(TF) -chdir=platform apply

pki-init:
	$(TF) -chdir=pki init

pki-plan:
	$(TF) -chdir=pki plan

pki-apply:
	$(TF) -chdir=pki apply

rotate-rekey:
	./pki/rotate.sh rekey

rotate-recreate:
	./pki/rotate.sh recreate
