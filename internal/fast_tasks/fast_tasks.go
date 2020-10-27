
package fast_tasks

import(
    ansible "github.com/lucabodd/go-ansible"
    "context"
    "encoding/base64"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "log"
    "os"
    "os/user"
    "strings"
    . "github.com/lucabodd/maicsd/pkg/utils"
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

type User struct {
	Sys_username string `bson:"sys_username"`
	Email string `bson:"email"`
	Role string `bson:"role"`
	Key_last_unlock string `bson:"key_last_unlock"`
	PubKey string `bson:"pubKey"`
	Password string `bson:"password"`
	Otp_secret string `bson:"otp_secret"`
	PwdChangedTime string `bson:"pwdChangedTime"`
	PwdAccountLockedTime *string `bson:"pwdAccountLockedTime"`
}

/***************************************
                Functions
****************************************/

//generate ~/.ssh/config file according to hosts stored in mongodb
func SshConfigGenerator(mdb *mongo.Client, mongo_instance string, skdc_user string){
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
	   bc, err = f.WriteString("    User "+skdc_user+"\n")
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

//Access control deploy -> write sshd config file
func AccessControlDeploy(mdb *mongo.Client, mongo_instance string, skdc_user string, skdc_dir string ){
	log.Println("[*] Undergoing Access deploy to managed hosts")
	log.Println(" |___")

	// vars
	findOptions := options.Find()
	var conn string
	error := ""

	// Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")
	access_users := mdb.Database(mongo_instance).Collection("access_users")
    access_groups := mdb.Database(mongo_instance).Collection("access_groups")
	users := mdb.Database(mongo_instance).Collection("users")

	// Get all Hosts
	var res_hosts []*Host
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1, "port": 1})
	cur, err := hosts.Find(context.TODO(), bson.D{{}}, findOptProj)
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
                               },
		}

		res, err := playbook.Run()
		error = ""
		//read connection status
		if err != nil {
            error = res.RawStdout
			if (strings.Contains(res.RawStdout, "Missing sudo") || strings.Contains(res.RawStdout, "password is required to run sudo") || strings.Contains(res.RawStdout, "sudo: not found")) {
				conn = "SUDOERR"
                error = "Shared connection to 10.60.0.170 closed. /bin/sh: 1: sudo: not found"
			} else if(strings.Contains(res.RawStdout, "Failed to connect") || res.Unreachable > 0){
				conn = "EARLY-FAIL"
                log.Println(res)
                log.Println(err)
                Kill(1)
			} else if(strings.Contains(res.RawStdout, "CLI-UNDEPLOYED")){
				conn = "CLI-UNDEPLOYED"
                log.Println(res.RawStdout)
                log.Println(err)
			} else {
				conn = "UNKNOWN"
                log.Println(res.RawStdout)
                log.Println(err)
			}
			//logging
			if error != "" {
				log.Println("    |- "+h.Hostname+" Error establishing connection, detected error "+conn+" might be fixed in SKDC host-mgmt")
			}
		} else {
			conn = "TRUE"
		}
		error = strings.Replace(error, "\n", "", -1)
		error = strings.Replace(error, "  ", "", -1)
		error = base64.StdEncoding.EncodeToString([]byte(error))
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$set": bson.M{ "connection" : conn, "error": error }})
		Check(err)
	}
	log.Println("    |[+] Access control deployed according to SKDC user defined rules")
}

func MaicsWardsDeploy(mdb *mongo.Client, mongo_instance string, skdc_user string, skdc_dir string, base_dn string, ldap_host string, bind_dn string, bind_password string) {
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
        playbook := &ansible.PlaybookCmd{
			Playbook:          skdc_dir+"ansible/playbooks/skdc-ward-deploy.yml",
			ConnectionOptions: &ansible.PlaybookConnectionOptions{},
			Options:           &ansible.PlaybookOptions{
                        			Inventory: skdc_dir+"ansible/inventory",
                        			Limit: h.Hostname,
                        			ExtraVars: map[string]interface{}{
                        				"base": base_dn,
                        				"host": ldap_host,
                        				"bind_dn": bind_dn,
                        				"bind_password": bind_password,
                        		    },
		                        },
        }
		_, err = playbook.Run()
		Check(err)
		log.Println("    |- client deployed to: "+h.Hostname)
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$unset": bson.M{ "deploy_req" : 1}})
		Check(err)
	}
	log.Println("[+] skdc-ward deployed according to SKDC requests")
}
