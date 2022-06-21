package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"github.com/bitfield/script"
	"golang.org/x/crypto/ssh"
)

const (
	context            = "k3s-cluster"
	osVersion          = "20.04"
	cpu                = 4
	memory             = "4G"
	kubeConfigFileName = "k3s.yaml"
	tempfolder         = "/tmp"
	keyName            = "k3s"
	workerCount        = 2
)

type configuration struct {
	User         string
	SSHPublicKey string
}

var cloudInitTemplate = `users:
- name: {{ .User }}
  groups: sudo
  sudo: ALL=(ALL) NOPASSWD:ALL
  ssh_authorized_keys: 
  - {{ .SSHPublicKey }}
`

var programs = []string{"multipass", "k3sup", "helm"}

var config configuration
var masterIP string

func init() {
	for _, i := range programs {
		checkProgramExists(i)
	}
}

func checkProgramExists(p string) {
	_, err := exec.LookPath(p)
	if err != nil {
		log.Fatalln(err)
	}
}

func makeSSHKeyPair(key string) {
	_, err1 := os.Stat(key)
	_, err2 := os.Stat(key + ".pub")
	if err1 == nil && err2 == nil {
		log.Printf("A Key Pair already exists in %v\n", tempfolder)
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalln(err)
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(key)
	if err != nil {
		log.Fatalln(err)
	}
	defer privateKeyFile.Close()
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		log.Fatalln(err)
	}
	script.Exec("chmod 0600 " + key)

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalln(err)
	}
	err = ioutil.WriteFile(key+".pub", ssh.MarshalAuthorizedKey(pub), 0655)
	if err != nil {
		log.Fatalln(err)
	}

}

func createCloudInitFile() {
	s, _ := script.File(filepath.Join(tempfolder, keyName+".pub")).String()
	config := configuration{
		User:         os.Getenv("USER"),
		SSHPublicKey: s,
	}

	outputPath := "cloudinit.yaml"
	f, err := os.Create(outputPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	t, err := template.New("cloudinit").Parse(cloudInitTemplate)
	if err != nil {
		log.Fatalln(err)
	}
	err = t.Execute(f, config)
	if err != nil {
		log.Fatalln(err)
	}
}

func createVM(vms []string) {
	cmd := fmt.Sprintf("multipass launch -c %v -m %v -n NAME %v --cloud-init %v",
		cpu,
		memory,
		osVersion,
		"cloudinit.yaml",
	)

	for _, i := range vms {
		c := strings.Replace(cmd, "NAME", i, 1)
		script.Exec(c).Stdout()
	}
}

func installMaster() {
	ip, err := script.Exec("multipass list").Match("master").Column(3).String()
	if err != nil {
		log.Fatalln(err)
	}
	masterIP = cleanString(ip)
	cmd := fmt.Sprintf("k3sup install --ip %v --context %v --user %v --ssh-key %v",
		masterIP,
		context,
		config.User,
		filepath.Join(tempfolder, keyName),
	)
	script.Exec(cmd).Stdout()
}

func installWorkers(w []string) {
	for _, i := range w {
		wip, err := script.Exec("multipass list").Match(i).Column(3).String()
		if err != nil {
			log.Fatalln(err)
		}
		cmd := fmt.Sprintf("k3sup join --server-ip %v --ip %v --user %v --ssh-key %v",
			masterIP,
			cleanString(wip),
			config.User,
			filepath.Join(tempfolder, keyName),
		)
		script.Exec(cmd).Stdout()
	}
}

func getKubeConfig() {
	cmd := fmt.Sprintf("ssh -o StrictHostKeyChecking=no %v@%v -i %v 'sudo cat /etc/rancher/k3s/k3s.yaml'",
		config.User,
		masterIP,
		filepath.Join(tempfolder, keyName),
	)
	_, err := script.Exec(cmd).Replace("127.0.0.1:6443", masterIP+":6443").Replace("default", context).AppendFile(filepath.Join(os.Getenv("HOME"), ".kube", kubeConfigFileName))
	if err != nil {
		log.Fatalln(err)
	}
	os.Setenv("KUBECONFIG", filepath.Join(os.Getenv("HOME"), ".kube", kubeConfigFileName))
}

func installFalco() {
	if _, err := script.Exec("helm repo update").Stdout(); err != nil {
		log.Fatalln(err)
	}

	cmd := "helm install falco falcosecurity/falco --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=true -n falco --set \"extraArgs={-U}\" --set kubernetesSupport.enableNodeFilter=false --set falcosidekick.replicaCount=1 --set falcosidekick.webui.replicaCount=1 --create-namespace"
	if _, err := script.Exec(cmd).Stdout(); err != nil {
		log.Fatalln(err)
	}
}

func cleanString(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	return s
}

func main() {
	log.Println("Create Key Pair")
	makeSSHKeyPair(filepath.Join(tempfolder, keyName))

	s, _ := script.File(filepath.Join(tempfolder, keyName+".pub")).String()
	config = configuration{
		User:         os.Getenv("USER"),
		SSHPublicKey: s,
	}

	log.Println("Create Cloud Init file")
	createCloudInitFile()

	var workers []string
	for i := 1; i <= workerCount; i++ {
		workers = append(workers, fmt.Sprintf("worker%v", i))
	}

	log.Println("Create VM")
	createVM(append(workers, "master"))
	log.Println("Install Master")
	installMaster()
	log.Println("Install Workers")
	installWorkers(workers)
	log.Println("Get KubeConfig (" + filepath.Join(os.Getenv("HOME"), ".kube", kubeConfigFileName) + ")")
	getKubeConfig()
	log.Println("Install Falco + Falcosidekick")
	installFalco()
}
