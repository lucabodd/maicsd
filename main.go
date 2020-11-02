package main

import (
	"flag"
	"github.com/sevlyar/go-daemon"
  	"go.mongodb.org/mongo-driver/mongo"
  	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"syscall"
	"time"
	"encoding/json"
	"context"
	fast_tasks "github.com/lucabodd/maicsd/internal/fast_tasks"
	slow_tasks "github.com/lucabodd/maicsd/internal/slow_tasks"
	daily_tasks "github.com/lucabodd/maicsd/internal/daily_tasks"
	ldap_client "github.com/lucabodd/go-ldap-client"
	. "github.com/lucabodd/maicsd/pkg/utils"
	"strings"
)

var (
	signal = flag.String("s", "", `Send signal to the daemon:
		quit - graceful shutdown
  		stop - fast shutdown
  		reload - reloading the configuration file`)
)
type Configuration struct {
	Maics struct {
		Dir     string
		Log_dir string
		Run_dir string
		User	string
		Admin_mail string
		Ssh_key_lifetime int
	}
	Mongo struct {
		Url 	string
		Instance string
	}
	Ldap struct {
		Uri 	string
		TLS	struct {
			CA string
            KEY string
            CERT string
		}
		Base_dn string
		Bind_dn string
		Bind_password string
		Read_only_dn string
		Read_only_password string
	}
}

func main() {
	//parsing flags
	c := flag.String("c", "","Specify the configuration file.")
    flag.Parse()

	//Parsing system signaling
	daemon.AddCommand(daemon.StringFlag(signal, "quit"), syscall.SIGQUIT, termHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "reload"), syscall.SIGHUP, reloadHandler)

	file, err := os.Open(*c)
	if err != nil {
		log.Fatal("[-] Can't open config file: ", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	Config := Configuration{}
	err = decoder.Decode(&Config)
	if err != nil {
		log.Fatal("[-] Can't decode config JSON: ", err)
	}

    cntxt := &daemon.Context{
		PidFileName: Config.Maics.Run_dir+"maics.pid",
		PidFilePerm: 0644,
		LogFileName: Config.Maics.Log_dir+"daemon.log",
		LogFilePerm: 0640,
		//WorkDir:     Config.Maics.Dir+"daemons/",
		Umask:       027,
		Args:        []string{},
	}

    if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		Check(err)
		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	Check(err)
	if d != nil {
		return
	}
	defer cntxt.Release()

	log.Println("[+] Releasing OS pid")
	log.Println("+ - - - - - - - - - - - - - - - - - - -+")
	log.Println("|  SKDC host controller daemon started |")
    log.Println("+ - - - - - - - - - - - - - - - - - - -+")

	go worker(Config)

	err = daemon.ServeSignals()
	Check(err)

    log.Println("+ - - - - - - - - - - - - - - - - - - - - +")
	log.Println("| SKDC host controller daemon terminated  |")
    log.Println("+ - - - - - - - - - - - - - - - - - - - - +")
}

var (
	stop = make(chan struct{})
	done = make(chan struct{})
)

func worker(Config Configuration) {
LOOP:
	for {
		//Object declarations, needed for tasks
		//MongoDB setup
		clientOptions := options.Client().ApplyURI(Config.Mongo.Url)
		mdb, err := mongo.Connect(context.TODO(), clientOptions)
		Check(err)

		//LDAP setup
		host := strings.Split(Config.Ldap.Uri, "//")[1]
		ldap := &ldap_client.LDAPClient{
			Base:         Config.Ldap.Base_dn,
			Host:         host,
			Port:         636,
			UseSSL:       true,
	        InsecureSkipVerify: true,
			BindDN:       Config.Ldap.Bind_dn,
			BindPassword: Config.Ldap.Bind_password,
			UserFilter:   "(uid=%s)",
			GroupFilter: "(memberUid=%s)",
			Attributes:   []string{},
		}

		// Check the DB connection
		err = mdb.Ping(context.TODO(), nil)
		Check(err)

		t1:=time.Now()
		t2:=time.Now()
		t3:=time.Now()
		t4:=time.Now()
		for int(t3.Sub(t4).Minutes()) <= 1440 {
			for int(t2.Sub(t1).Minutes()) <= 10 {
				// Quick tasks, below are executed instantly
				fast_tasks.SshConfigGenerator(mdb, Config.Mongo.Instance, Config.Maics.User)
				fast_tasks.AnsibleInventoryGenerator(mdb, Config.Mongo.Instance, Config.Maics.Dir )
				fast_tasks.MaicsWardsDeploy(mdb, Config.Mongo.Instance, Config.Maics.User, Config.Maics.Dir, Config.Ldap.Uri, Config.Ldap.TLS.CA, Config.Ldap.Base_dn, Config.Ldap.Read_only_dn, Config.Ldap.Read_only_password)
				fast_tasks.AccessControlDeploy(mdb, Config.Mongo.Instance, Config.Maics.User,Config.Maics.Dir )
				t2=time.Now()
				// instantly quit when reciveing SIGTERM
				select {
					case <-stop:
						break LOOP
					default:
				}
			}
			//tasks below are executed every 10 minutes
			// cypher ssh key if expired
			slow_tasks.SshKeyExpire(mdb, Config.Mongo.Instance, ldap, Config.Maics.Ssh_key_lifetime)
			// sync pwdAccountLockedTime and pwdChangedTime
			slow_tasks.LdapSync(mdb, Config.Mongo.Instance, ldap)
			//gen xlsx
			slow_tasks.AccessMatrixReport(Config.Maics.Dir)

		    log.Println("[+] .xlsx report generated successfully")
			t1=time.Now()
			t2=time.Now()
			t3=time.Now()
		}
		//tasks below are executed daily
		daily_tasks.PasswordExpire(mdb, Config.Mongo.Instance, Config.Maics.Dir, Config.Maics.Admin_mail, ldap)

		t4=time.Now()
	}
	done <- struct{}{}
}

//System signaling handling
func termHandler(sig os.Signal) error {
	log.Println("[*] System SIGQUIT recived, Terminating daemon sshd config on remote hosts won't be updated anymore...")
	log.Println("+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+")
	log.Println("|       SIGQUIT: gracefully terminating pending processes          |")
    log.Println("+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+")
	stop <- struct{}{}
	if sig == syscall.SIGQUIT {
		<-done
	}
	return daemon.ErrStop
}

func reloadHandler(sig os.Signal) error {
	log.Println("[*] System SIGHUP recived reloading configuration ...")
	return nil
}
