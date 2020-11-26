
package fast_tasks

import(
    ansible "github.com/lucabodd/go-ansible"
    "context"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "log"
    "os"
    "os/user"
    "strings"
    "time"
    . "github.com/lucabodd/maicsd/pkg/utils"
    json "github.com/tidwall/gjson"
)

/***************************************
                Structs
****************************************/

type Host struct {
	Hostname string `bson:"hostname"`
	Ip string `bson:"ip"`
	Port string `bson:"port"`
	Proxy string `bson:"proxy"`
}

type Hostgroup struct {
	Name string `bson:"name"`
	Members []Host
}

type Access_group struct {
	Group string `bson:"group"`
	Hostname string `bson:"hostname"`
}

type Access_user struct {
    Sys_username string `bson:"sys_username"`
	Email string `bson:"email"`
    Name string `bson:"name"`
    Surname string `bson:"surname"`
    Hostname string `bson:"hostname"`
}

type Command_set struct {
    Name string `bson:"name"`
    Commands []Command
}

type Command struct {
    Path string `bson:"path"`
    Access_mode string `bson:"access_mode"`
}

type Confinement_shell struct {
    Name string `bson:"name"`
    Mode string `bson:"mode"`
    Command_sets []string `bson:"command_sets"`
}

type User struct {
	Sys_username string `bson:"sys_username"`
	Email string `bson:"email"`
	Role string `bson:"role"`
	Key_last_unlock string `bson:"key_last_unlock"`
	PubKey string `bson:"sshPublicKey"`
	Password string `bson:"password"`
	Otp_secret string `bson:"otp_secret"`
	PwdChangedTime string `bson:"pwdChangedTime"`
	PwdAccountLockedTime *string `bson:"pwdAccountLockedTime"`
}

/***************************************
                Functions
****************************************/

//generate ~/.ssh/config file according to hosts stored in mongodb
func SshConfigGenerator(mdb *mongo.Client, mongo_instance string){
	log.Println("[*] Generating ssh config")
	//vars
	bt := 0
	usr, err := user.Current()
	Check(err)
	f, err := os.Create(usr.HomeDir +"/.ssh/config")
	Check(err)
	defer f.Close()

	//Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")

	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1,"proxy":1, "port":1, "ip":1})
	cur, err := hosts.Find(context.TODO(), bson.D{{}}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   Check(err)
	   bc, err := f.WriteString("Host "+host.Hostname+"\n")
	   bt += bc
	   Check(err)
	   bc, err = f.WriteString("    User root\n")
	   bt += bc
	   Check(err)
	   if(host.Proxy == "none") {
		   bc, err = f.WriteString("    HostName "+host.Ip+"\n")
		   bt += bc
		   Check(err)
		   bc, err = f.WriteString("    Port "+host.Port+"\n")
		   bt += bc
		   Check(err)
	   } else {
		   bc, err = f.WriteString("    HostName "+host.Hostname+"\n")
		   bt += bc
		   Check(err)
		   bc, err = f.WriteString("    ProxyCommand ssh "+host.Proxy+" -W "+host.Ip+":"+host.Port+" \n")
		   bt += bc
		   Check(err)
	   }
	   bc, err = f.WriteString("\n")
	   bt += bc
	   Check(err)
	}
	f.Sync()
	log.Println("    |- bytes written:", bt)
	log.Println("[+] SSH config generated according to MongoDB")
}

//generate ansible inventory file according to hosts stored in mongodb
func AnsibleInventoryGenerator(mdb *mongo.Client, mongo_instance string, skdc_dir string){
	log.Println("[*] Generating ansible inventory")
	// vars
	findOptions := options.Find()
	f, err := os.Create(skdc_dir+"ansible/inventory")
	Check(err)
	defer f.Close()
	bt := 0

	//Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")
	hostgroups := mdb.Database(mongo_instance).Collection("hostgroups")

	cur, err := hostgroups.Find(context.TODO(), bson.D{{}}, findOptions)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var hostgroup Hostgroup
	   err := cur.Decode(&hostgroup)
	   Check(err)
	   bc, err := f.WriteString("["+hostgroup.Name+"]\n")
	   bt += bc
	   Check(err)
	   for _,h := range hostgroup.Members {
		   bc, err := f.WriteString(h.Hostname+"\n")
		   Check(err)
		   bt += bc
	   }
	   f.WriteString("\n")
	}
	err = cur.Err()
	Check(err)

	// write ungrouped hosts
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1})
	cur, err = hosts.Find(context.TODO(), bson.M{"hostgroup": "none"}, findOptProj)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var host Host
		err := cur.Decode(&host)
 	   	Check(err)
 	   	bc, err := f.WriteString(host.Hostname+"\n")
		Check(err)
		bt += bc
 	}
	f.Sync()
	log.Println("    |- bytes written:", bt)
	log.Println("[+] Ansible inventory generated according to MongoDB")
}


func GatherHostsFacts(mdb *mongo.Client, mongo_instance string, skdc_dir string ){
    log.Println("[*] Undergoing Host Fact gathering")
	log.Println(" |___")

	// vars
	var conn string
	connection_detail := ""

	// Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")

	// Get all Hosts without a deploy req SYN
	var res_hosts []*Host
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1, "port": 1 })
	cur, err := hosts.Find(context.TODO(), bson.M{ "deploy_req": bson.M{ "$exists": false }, "connection" : bson.M{"$ne": "true" } }, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   Check(err)
	   res_hosts = append(res_hosts, &host)
	}
	err = cur.Err()
	Check(err)

    //removing ansible caches directory
    usr, err := user.Current()
    Check(err)
    err = os.RemoveAll(usr.HomeDir+"/.ansible/")
    SoftCheck(err)


	// Iterate trough all hosts and define ACL_users
	for _, h := range res_hosts {
		playbook := &ansible.PlaybookCmd{
			Playbook:          skdc_dir+"ansible/playbooks/gather-hosts-facts.yml",
			ConnectionOptions: &ansible.PlaybookConnectionOptions{},
			Options:           &ansible.PlaybookOptions{
    			                     Inventory: skdc_dir+"ansible/inventory",
    			                     Limit: h.Hostname,
    			                     ExtraVars: map[string]interface{}{},
                                    FlushCache: true,
                               },
		}

		res, err := playbook.Run()
		//read connection status
		if err != nil {
            if(res.Unreachable > 0){
                if (strings.Contains(res.RawStdout, "ssh_exchange_identification")) {
                    conn = "proxy-refuse"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else if(strings.Contains(res.RawStdout, "No route to host") || strings.Contains(res.RawStdout, "Connection refused") || strings.Contains(res.RawStdout, "Connection timed out")){
                    conn = "unreachable"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else if (strings.Contains(res.RawStdout, "Permission denied (publickey")) {
                    conn = "unauthorized"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else {
                    conn = "unknown"
                    log.Println("ANSIBLE RUN ERROR -> ")
                    log.Print(err)
                    log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts").String()
                }
            } else if (res.Failures > 0) {
                if (strings.Contains(res.RawStdout, "maics-ward-undeployed")){
                    conn = "maics-ward-undeployed"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.1.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else {
                    conn = "unknown"
                    log.Println("ANSIBLE RUN ERROR -> ")
                    log.Print(err)
                    log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts").String()
                }
            } else {
                conn = "unknown"
                log.Println("ANSIBLE RUN ERROR -> ")
                log.Print(err)
                log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts").String()
            }
			//logging
			if connection_detail != "" {
				log.Println("    |- "+h.Hostname+" Error establishing connection, detected error "+conn+" might be fixed in MAICS host-mgmt")
			}
		} else {
			conn = "true"
            //format := "2020-10-29T23:56:32.777053Z"
			now := time.Now().Format(time.RFC3339)
            connection_detail = "Connected.<br>Access control last update: "+ now

		}
		connection_detail = strings.Replace(connection_detail, "\n", "", -1)
		connection_detail = strings.Replace(connection_detail, "  ", "", -1)
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$set": bson.M{ "connection" : conn, "connection_detail": connection_detail }})
		Check(err)
	}
	log.Println("    |[+] Gathered Host facts for unconnected hosts")
}

//Access control deploy -> write sshd config file
func AccessControlDeploy(mdb *mongo.Client, mongo_instance string, skdc_user string, skdc_dir string ){
	log.Println("[*] Undergoing Access deploy to managed hosts")
	log.Println(" |___")

	// vars
	findOptions := options.Find()
	var conn string
	connection_detail := ""

	// Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")
	access_users := mdb.Database(mongo_instance).Collection("access_users")
    access_groups := mdb.Database(mongo_instance).Collection("access_groups")
	users := mdb.Database(mongo_instance).Collection("users")

	// Get all Hosts without a deploy req SYN
	var res_hosts []*Host
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1, "port": 1 })
	cur, err := hosts.Find(context.TODO(), bson.M{ "connection": "true", "deploy_req": bson.M{ "$exists": false }}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   Check(err)
	   res_hosts = append(res_hosts, &host)
	}
	err = cur.Err()
	Check(err)

    //removing ansible caches directory
    usr, err := user.Current()
    Check(err)
    err = os.RemoveAll(usr.HomeDir+"/.ansible/")
    SoftCheck(err)


	// Iterate trough all hosts and define ACL_users
	for _, h := range res_hosts {
		ACL_users := []string {}
        ACL_groups := []string {}

        //find users with access right to the host
		cur, err = access_users.Find(context.TODO(), bson.M{"hostname":h.Hostname}, findOptions)
		Check(err)
		defer cur.Close(context.TODO())
		for cur.Next(context.TODO()) {
		   var access_entry Access_user
		   err := cur.Decode(&access_entry)
		   Check(err)
		   ACL_users = append(ACL_users, access_entry.Sys_username)
		}
		err := cur.Err()
		Check(err)

		//find admins (Has system wide access)
		findOptProj := options.Find().SetProjection(bson.M{"sys_username": 1})
		cur, err = users.Find(context.TODO(), bson.M{"role":"admin"}, findOptProj)
		defer cur.Close(context.TODO())
		for cur.Next(context.TODO()) {
		   var user User
		   err := cur.Decode(&user)
		   Check(err)
		   ACL_users = append(ACL_users, user.Sys_username)
		}
		err = cur.Err()
		Check(err)

        //add default MAICS user and root
        ACL_users = append(ACL_users, skdc_user)
        ACL_users = append(ACL_users, "root")

        ACL_users_string := strings.Join(ACL_users[:], " ")

        //find groups with access right to the host
		findOptProj = options.Find().SetProjection(bson.M{"group": 1})
		cur, err = access_groups.Find(context.TODO(), bson.M{"hostname":h.Hostname}, findOptProj)
		defer cur.Close(context.TODO())
		for cur.Next(context.TODO()) {
		   var access_entry Access_group
		   err := cur.Decode(&access_entry)
		   Check(err)
		   ACL_groups = append(ACL_groups, access_entry.Group)
		}
		err = cur.Err()
		Check(err)

        //conmposing /etc/ssh/sshd_config access string
        sshd_config_access := "AllowUsers " + ACL_users_string + "\n"
        for _ , group_entry := range ACL_groups {
			sshd_config_access += "Match Group "+group_entry+"\n     AllowUsers *\n"
		}

		playbook := &ansible.PlaybookCmd{
			Playbook:          skdc_dir+"ansible/playbooks/sshd-config-deploy.yml",
			ConnectionOptions: &ansible.PlaybookConnectionOptions{},
			Options:           &ansible.PlaybookOptions{
    			                     Inventory: skdc_dir+"ansible/inventory",
    			                     Limit: h.Hostname,
    			                     ExtraVars: map[string]interface{}{
    				                                "sshd_allow_block": sshd_config_access,
    				                                "maics_ssh_port": h.Port,
    			                                 },
                                    FlushCache: true,
                               },
		}

        //reparsing connection status as in GatherHostsFacts in order to check if host is still alive
		res, err := playbook.Run()
        if err != nil {
            if(res.Unreachable > 0){
                if (strings.Contains(res.RawStdout, "ssh_exchange_identification")) {
                    conn = "proxy-refuse"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else if(strings.Contains(res.RawStdout, "No route to host") || strings.Contains(res.RawStdout, "Connection refused") || strings.Contains(res.RawStdout, "Connection timed out")){
                    conn = "unreachable"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else if (strings.Contains(res.RawStdout, "Permission denied (publickey")) {
                    conn = "unauthorized"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else {
                    conn = "unknown"
                    log.Println("ANSIBLE RUN ERROR -> ")
                    log.Print(err)
                    log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts").String()
                }
            } else if (res.Failures > 0) {
                if (strings.Contains(res.RawStdout, "maics-ward-undeployed")){
                    conn = "maics-ward-undeployed"
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.1.hosts.*.msg").String()
                    // Adding start & end time
                    connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                    connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
                } else {
                    conn = "unknown"
                    log.Println("ANSIBLE RUN ERROR -> ")
                    log.Print(err)
                    log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                    connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts").String()
                }
            } else {
                conn = "unknown"
                log.Println("ANSIBLE RUN ERROR -> ")
                log.Print(err)
                log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts").String()
            }
			//logging
			if connection_detail != "" {
				log.Println("    |- "+h.Hostname+" Error establishing connection, detected error "+conn+" might be fixed in MAICS host-mgmt")
			}
		} else {
			conn = "true"
            //format := "2020-10-29T23:56:32.777053Z"
			now := time.Now().Format(time.RFC3339)
            connection_detail = "Connected.<br>Access control last update: "+ now

		}
		connection_detail = strings.Replace(connection_detail, "\n", "", -1)
		connection_detail = strings.Replace(connection_detail, "  ", "", -1)
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$set": bson.M{ "connection" : conn, "connection_detail": connection_detail }})
		Check(err)
	}
	log.Println("    |[+] Access control deployed")
}

func MaicsWardsDeploy(mdb *mongo.Client, mongo_instance string, skdc_user string, skdc_dir string, ldap_uri string, ldap_tls_ca string, ldap_base_dn string, ldap_read_only_dn string, ldap_read_only_password string) {
	log.Println("[*] Undergoing client deployment")
	log.Println(" |___")

	// Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")

	// Get all Hosts
	var res_hosts []*Host
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1})
	cur, err := hosts.Find(context.TODO(), bson.M{ "deploy_req": bson.M{ "$exists": true }}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   Check(err)
	   res_hosts = append(res_hosts, &host)
	}
	err = cur.Err()
	Check(err)

	for _, h := range res_hosts {
        //removing ansible caches directory
        usr, err := user.Current()
    	Check(err)
        err = os.RemoveAll(usr.HomeDir+"/.ansible/")
        Check(err)

        //Deploying ldap client
        playbook := &ansible.PlaybookCmd{
			Playbook:          skdc_dir+"ansible/playbooks/ldap-client.yml",
			ConnectionOptions: &ansible.PlaybookConnectionOptions{},
			Options:           &ansible.PlaybookOptions{
                        			Inventory: skdc_dir+"ansible/inventory",
                        			Limit: h.Hostname,
                        			ExtraVars: map[string]interface{}{
                        				"ldap_tls_ca": ldap_tls_ca,
                        				"ldap_uri": ldap_uri,
                                        "ldap_base_dn": ldap_base_dn,
                        				"ldap_read_only_dn": ldap_read_only_dn,
                        				"ldap_read_only_password": ldap_read_only_password,
                        		    },
		                        },
        }
        _, err = playbook.Run()
		SoftCheck(err)
        log.Println("    |- LDAP client deployed to: "+h.Hostname)

        playbook = &ansible.PlaybookCmd{
			Playbook:          skdc_dir+"ansible/playbooks/maics-ward-deploy.yml",
			ConnectionOptions: &ansible.PlaybookConnectionOptions{},
			Options:           &ansible.PlaybookOptions{
                        			Inventory: skdc_dir+"ansible/inventory",
                        			Limit: h.Hostname,
                        			ExtraVars: map[string]interface{}{
                        				"ldap_base_dn": ldap_base_dn,
                        				"ldap_uri": ldap_uri,
                        				"ldap_read_only_dn": ldap_read_only_dn,
                        				"ldap_read_only_password": ldap_read_only_password,
                                        "maics_user": skdc_user,
                        		    },
		                        },
        }
		_, err = playbook.Run()
		SoftCheck(err)
		log.Println("    |- client deployed to: "+h.Hostname)
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$unset": bson.M{ "deploy_req" : 1}})
		Check(err)
	}
	log.Println("[+] maics-ward deployed according to MAICS requests")
}

func ConfinementShellDeploy(mdb *mongo.Client, mongo_instance string, skdc_dir string) {
	log.Println("[*] Undergoing confinement shell deployment")
	log.Println(" |___")

    // Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")
    confinement_shells := mdb.Database(mongo_instance).Collection("confinement_shells")
    command_sets := mdb.Database(mongo_instance).Collection("command_sets")

    // Get all Hosts and generate string for limiting inventory
	var res_hosts []string
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1})
	cur, err := hosts.Find(context.TODO(), bson.M{ "connection": "true"}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
    for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   Check(err)
	   res_hosts = append(res_hosts, host.Hostname)
	}
	err = cur.Err()
	Check(err)

    if(len(res_hosts)>0){
        findOptProj = options.Find()
    	cur, err = confinement_shells.Find(context.TODO(), bson.D{{}}, findOptProj)
        Check(err)
    	defer cur.Close(context.TODO())
        for cur.Next(context.TODO()) {
    	   var shell Confinement_shell
    	   err := cur.Decode(&shell)
    	   Check(err)

           //get all commands assigned to a shell useing command_sets array
           var all_commands [] string
           for _, command_set_name := range shell.Command_sets {
               findOptProj = options.Find()
           	   curs, err := command_sets.Find(context.TODO(), bson.M{ "name": command_set_name }, findOptProj)
               Check(err)
           	   defer curs.Close(context.TODO())
               for curs.Next(context.TODO()) {
           	       var cs Command_set
           	       err := curs.Decode(&cs)
           	       Check(err)
                   for _, cmd := range cs.Commands {
                       all_commands = append(all_commands, cmd.Path+" "+cmd.Access_mode+",")
                   }
               }
           }

           //Deploy restricted shell
           playbook := &ansible.PlaybookCmd{
               Playbook:          skdc_dir+"ansible/playbooks/confinement-shells-deploy.yml",
               ConnectionOptions: &ansible.PlaybookConnectionOptions{},
               Options:           &ansible.PlaybookOptions{
                                       Inventory: skdc_dir+"ansible/inventory",
                                       Limit: strings.Join(res_hosts[:],","),
                                       ExtraVars: map[string]interface{}{
                                           "shell_name": shell.Name,
                                           "default_shell": "/bin/bash",
                                           "shell_mode": shell.Mode,
                                           "command_sets": strings.Join(all_commands[:], "\n  "),
                                       },
                                   },
           }
           _, err = playbook.Run()
           SoftCheck(err)
    	}
    	err = cur.Err()
    	Check(err)
        log.Println("    |[+] Restricted shell deployed to connected host ")
    } else{
        log.Println("    |[*] MAICS not managing any host yet. ")
    }
}
