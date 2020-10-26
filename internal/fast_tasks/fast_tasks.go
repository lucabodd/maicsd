
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
	access := mdb.Database(mongo_instance).Collection("access")
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

	// Iterate trough all hosts and define ACL
	for _, h := range res_hosts {
		ACL := []*User{}
		cur, err = access.Find(context.TODO(), bson.M{"hostname":h.Hostname}, findOptions)
		Check(err)
		defer cur.Close(context.TODO())
		for cur.Next(context.TODO()) {
		   var user User
		   err := cur.Decode(&user)
		   Check(err)
		   ACL = append(ACL, &user)
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
		   ACL = append(ACL, &user)
		}
		err = cur.Err()
		Check(err)

		// get all users in string
		ACL_string := skdc_user + " root"
		for _,a := range ACL {
			ACL_string = ACL_string + " " + a.Sys_username
		}
		b64_banner := base64.StdEncoding.EncodeToString([]byte(h.Hostname))

		playbook := &ansible.PlaybookCmd{
			Playbook:          skdc_dir+"ansible/playbooks/sshd-config-deploy.yml",
			ConnectionOptions: &ansible.PlaybookConnectionOptions{},
			Options:           &ansible.PlaybookOptions{
    			                     Inventory: skdc_dir+"ansible/inventory",
    			                     Limit: h.Hostname,
    			                     ExtraVars: map[string]interface{}{
    				                                "sshd_users": ACL_string,
    				                                "port": h.Port,
    				                                "banner": b64_banner,
    			                                 },
                               },
		}

		res, err := playbook.Run()
        console.log(err)
		error = ""
		//read connection status
		if err != nil {
            error = res.RawStdout
			if (strings.Contains(res.RawStdout, "Missing sudo") || strings.Contains(res.RawStdout, "password is required to run sudo") || strings.Contains(res.RawStdout, "sudo: not found")) {
				conn = "SUDOERR"
			} else if(strings.Contains(res.RawStdout, "Failed to connect") || res.Unreachable > 0){
				conn = "EARLY-FAIL"
			} else if(strings.Contains(res.RawStdout, "CLI-UNDEPLOYED")){
				conn = "CLI-UNDEPLOYED"
			} else {
				conn = "UNKNOWN"
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
