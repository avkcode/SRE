# Extract Git metadata
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_REPO_URL := $(shell git config --get remote.origin.url || echo "local-repo")
ENV_LABEL := app.environment:$(ENV)
GIT_BRANCH_LABEL := app.git/branch:$(GIT_BRANCH)
GIT_COMMIT_LABEL := app.git/commit:$(GIT_COMMIT)
GIT_REPO_LABEL := app.git/repo:$(GIT_REPO_URL)
TEAM_LABEL := app.team:devops
OWNER_LABEL := app.owner:engineering
DEPLOYMENT_LABEL := app.deployment:nginx-controller
VERSION_LABEL := app.version:v1.23.0
BUILD_TIMESTAMP_LABEL := app.build-timestamp:$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
RELEASE_LABEL := app.release:stable
REGION_LABEL := app.region:us-west-2
ZONE_LABEL := app.zone:a
CLUSTER_LABEL := app.cluster:eks-prod
SERVICE_TYPE_LABEL := app.service-type:LoadBalancer
INSTANCE_LABEL := app.instance:nginx-controller-instance

# Combine all labels into a single list
LABELS := \
  $(ENV_LABEL) \
  $(GIT_BRANCH_LABEL) \
  $(GIT_COMMIT_LABEL) \
  $(GIT_REPO_LABEL) \
  $(TEAM_LABEL) \
  $(OWNER_LABEL) \
  $(DEPLOYMENT_LABEL) \
  $(VERSION_LABEL) \
  $(BUILD_TIMESTAMP_LABEL) \
  $(RELEASE_LABEL) \
  $(REGION_LABEL) \
  $(ZONE_LABEL) \
  $(CLUSTER_LABEL) \
  $(SERVICE_TYPE_LABEL) \
  $(INSTANCE_LABEL) \
  $(DESCRIPTION_LABEL)

# Function to convert the array into YAML format
define generate_labels
$(foreach label,$(LABELS),$(shell echo "$(label)" | sed 's/:/=/; s/=/:\ /'))
endef

# Example target to print the labels in YAML format
print-labels:
	@echo "metadata:"
	@echo "  labels:"
	@$(foreach label,$(LABELS),echo "    $(shell echo $(label) | sed 's/:/=/; s/=/:\ /')";)
