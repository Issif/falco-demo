# Introduction

This program will:

* create a `k3s` cluster with `multipass` (1 master + 2 workers)
* install `falco`, `falcosidekick` and `falcosidekick-ui` with `Helm`
* retrieve the `kubeconfig` file

# Requirements

* [Go](https://go.dev/)
* [Multipass](https://multipass.run)
* [k3sup](https://github.com/alexellis/k3sup)
* [Helm](https://helm.sh/)

# Install

`go run main.go`

# Clean up

`multipass delete --all && multipass purge`

# Author

Thomas Labarussias [@Issif](https://github.com/Issif)
