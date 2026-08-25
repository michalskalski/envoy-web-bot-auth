SHELL := /usr/bin/env bash

CLUSTER_NAME ?= envoy-web-bot-auth
KIND_KUBECONFIG ?= $(CURDIR)/.kind/$(CLUSTER_NAME).kubeconfig
IMAGE ?= envoy-web-bot-auth:dev
EG_VERSION ?= v1.9.0
EG_NAMESPACE ?= envoy-gateway-system
GATEWAY_NAMESPACE ?= default
GATEWAY_NAME ?= web-bot-auth
MANIFESTS ?= examples/kind/resources.yaml
PORT_FORWARD_PORT ?= 8888
ENVOY_SERVICE_SELECTOR = gateway.envoyproxy.io/owning-gateway-namespace=$(GATEWAY_NAMESPACE),gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME)
KUBECTL = kubectl --kubeconfig '$(KIND_KUBECONFIG)'
HELM = helm --kubeconfig '$(KIND_KUBECONFIG)'

.DEFAULT_GOAL := help

.PHONY: help check-tools cluster image load-image gateway up reload port-forward status down

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "%-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check-tools: ## Check that the local cluster tooling is installed.
	@for tool in docker kind helm kubectl; do \
		command -v $$tool >/dev/null || { echo "missing required tool: $$tool" >&2; exit 1; }; \
	done

cluster: check-tools ## Create the local kind cluster if it does not already exist.
	@mkdir --parents '$(dir $(KIND_KUBECONFIG))'
	@if kind get clusters | rg --fixed-strings --quiet --line-regexp '$(CLUSTER_NAME)'; then \
		echo "kind cluster $(CLUSTER_NAME) already exists"; \
		kind export kubeconfig --name '$(CLUSTER_NAME)' --kubeconfig '$(KIND_KUBECONFIG)'; \
	else \
		kind create cluster --name '$(CLUSTER_NAME)' --kubeconfig '$(KIND_KUBECONFIG)'; \
	fi

image: check-tools ## Build the local Envoy image containing the dynamic module.
	docker build --tag '$(IMAGE)' .

load-image: cluster image ## Load the local Envoy image into kind.
	kind load docker-image --name '$(CLUSTER_NAME)' '$(IMAGE)'

gateway: load-image ## Install or upgrade Envoy Gateway
	$(HELM) upgrade --install envoy-gateway oci://docker.io/envoyproxy/gateway-helm \
		--version '$(EG_VERSION)' \
		--namespace '$(EG_NAMESPACE)' \
		--create-namespace \
		--wait \
		--timeout 5m
	$(KUBECTL) rollout status deployment/envoy-gateway --namespace '$(EG_NAMESPACE)' --timeout=5m

up: gateway ## Create the cluster, build/load the image, install Envoy Gateway, and apply local resources.
	$(KUBECTL) apply --filename '$(MANIFESTS)'
	$(KUBECTL) wait --for=condition=Accepted gateway/'$(GATEWAY_NAME)' --namespace '$(GATEWAY_NAMESPACE)' --timeout=5m
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector '$(ENVOY_SERVICE_SELECTOR)' --timeout=5m
	$(KUBECTL) rollout status deployment/echo --namespace '$(GATEWAY_NAMESPACE)' --timeout=5m

port-forward: check-tools ## Forward the generated Envoy Service to localhost; stop with Ctrl-C.
	@service="$$($(KUBECTL) get service --namespace '$(EG_NAMESPACE)' --selector '$(ENVOY_SERVICE_SELECTOR)' --output jsonpath='{.items[0].metadata.name}')"; \
		test -n "$$service" || { echo "generated Envoy Service not found; run make up first" >&2; exit 1; }; \
		echo "forwarding $$service to http://127.0.0.1:$(PORT_FORWARD_PORT)"; \
		$(KUBECTL) port-forward --namespace '$(EG_NAMESPACE)' "service/$$service" '$(PORT_FORWARD_PORT):80'

reload: load-image ## Rebuild/reload the image and restart only the generated Envoy proxy.
	$(KUBECTL) rollout restart deployment --namespace '$(EG_NAMESPACE)' \
		--selector 'gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME)'
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector 'gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME)' --timeout=5m

status: check-tools ## Show kind clusters and the Envoy Gateway controller status.
	kind get clusters
	$(KUBECTL) get deployment,pods --namespace '$(EG_NAMESPACE)'
	$(KUBECTL) get gateway,httproute,envoyproxy,envoyextensionpolicy,service,deployment,pods --namespace '$(GATEWAY_NAMESPACE)'

down: check-tools ## Delete the local kind cluster.
	kind delete cluster --name '$(CLUSTER_NAME)'
