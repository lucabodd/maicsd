package slow_tasks

import (
    "encoding/base32"
    ldap_client "github.com/lucabodd/go-ldap-client"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "log"
    "context"
    . "github.com/lucabodd/maicsd/pkg/utils"
    "strings"
    "os/exec"
    "crypto/sha512"
	"encoding/hex"
)

type User struct {
	Sys_username string `bson:"sys_username"`
	Email string `bson:"email"`
	Role string `bson:"role"`
	Key_last_unlock string `bson:"key_last_unlock"`
	SshPublicKey string `bson:"sshPublicKey"`
	Password string `bson:"password"`
	Otp_secret string `bson:"otp_secret"`
    Token_publicKey string `bson:"token_publicKey"`
	PwdChangedTime string `bson:"pwdChangedTime"`
	PwdAccountLockedTime *string `bson:"pwdAccountLockedTime"`
}


//slow tasks
/************************************
	Task executed every 10 minutes
*************************************/
func SshKeyExpire(mdb *mongo.Client, mongo_instance string, ldap *ldap_client.LDAPClient, ssh_key_lifetime int){
	log.Println("[*] Undergoing key expiration procedure")
	log.Println(" |___")

	// vars
	users := mdb.Database(mongo_instance).Collection("users")
	expirationDelta := ssh_key_lifetime / 3600 // convert seconds to hours

	findOptProj := options.Find().SetProjection(bson.M{"sys_username":1, "email":1, "sshPublicKey": 1, "otp_secret":1, "token_publicKey":1, "key_last_unlock":1})
	cur, err := users.Find(context.TODO(), bson.M{ "sshPublicKey": bson.M{ "$exists": true, "$ne": "" }}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var user User
		err := cur.Decode(&user)
		Check(err)
        //redo
		diff := TimeHoursDiff(user.Key_last_unlock)
		if (diff >= expirationDelta) {
			//cipher string only if it is unciphered
			if(strings.Contains(user.SshPublicKey, "ssh-rsa")) {

                //calculate hashes to generate master key
                otp_secret_hash := ""
                token_secret_hash := ""
                //hash otp_secret
                if(user.Otp_secret != ""){
                    b32_decoded_otp_secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(user.Otp_secret) //return a byte string
    				Check(err)
                    sha_512 := sha512.New()
    	            sha_512.Write(b32_decoded_otp_secret)
                    otp_secret_hash=hex.EncodeToString(sha_512.Sum(nil))
                }

                //hash token_secret
                if (user.Token_publicKey != ""){
                    sha_512 := sha512.New()
                    sha_512.Write([]byte(user.Token_publicKey))
                    token_secret_hash = hex.EncodeToString(sha_512.Sum(nil))
                }

                //hash the hashes :D and generate key
                to_hash := otp_secret_hash+token_secret_hash
                sha_512 := sha512.New()
	            sha_512.Write([]byte(to_hash))
                key := hex.EncodeToString(sha_512.Sum(nil))

				encKey := AESencrypt(key, user.SshPublicKey)
				_, err = users.UpdateOne(context.TODO(), bson.M{"email":user.Email }, bson.M{ "$set": bson.M{ "sshPublicKey" : encKey}})
				Check(err)
				_, err = ldap.SetUserAttribute(user.Sys_username, "sshPublicKey", encKey)
				Check(err)
				log.Println("    |- SSH public key for user "+user.Sys_username+" Locked due to expiration")
			}
		}
	}
	log.Println("[+] Expired keys locked successfully")
}

func AccessMatrixReport (maics_dir string) {
    cmd := exec.Command("/usr/bin/python", maics_dir + "reports/scripts/group-host-access-matrix.py", maics_dir)
    err := cmd.Run()
    SoftCheck(err)
    cmd = exec.Command("/usr/bin/python", maics_dir + "reports/scripts/user-host-access-matrix.py", maics_dir)
    err = cmd.Run()
    SoftCheck(err)
    cmd = exec.Command("/usr/bin/python", maics_dir + "reports/scripts/robot-host-access-matrix.py", maics_dir)
    err = cmd.Run()
    SoftCheck(err)
}

func LdapSync(mdb *mongo.Client, mongo_instance string, ldap *ldap_client.LDAPClient) {
    log.Println("[*] Undergoing LDAP sync")
    log.Println(" |___")
    users := mdb.Database(mongo_instance).Collection("users")

    findOptProj := options.Find().SetProjection(bson.M{"sys_username": 1})
    cur, err := users.Find(context.TODO(), bson.M{}, findOptProj)
    Check(err)

    for cur.Next(context.TODO()) {
		var user User
		err := cur.Decode(&user)
		Check(err)
        locked, err_1 := ldap.GetUserAttribute(user.Sys_username, "pwdAccountLockedTime")
        SoftCheck(err_1)
        pwd_last_changed, err_2 := ldap.GetUserAttribute(user.Sys_username, "pwdChangedTime")
        SoftCheck(err_2)
        sshPublicKey, err_3 := ldap.GetUserAttribute(user.Sys_username, "sshPublicKey")
        SoftCheck(err_3)
        loginShell, err_4 := ldap.GetUserAttribute(user.Sys_username, "loginShell")
        SoftCheck(err_4)
        if(err_1 == nil && err_2 == nil && err_3 == nil && err_4 == nil){
            _, err = users.UpdateOne(context.TODO(), bson.M{"sys_username":user.Sys_username }, bson.M{ "$set": bson.M{"pwdAccountLockedTime": locked,
                                                                                                                       "pwdChangedTime": pwd_last_changed,
                                                                                                                       "sshPublicKey": sshPublicKey,
                                                                                                                       "loginShell": loginShell, }})
            Check(err)
            log.Println("    |- user "+user.Sys_username+" has been successfully synced from LDAP")
        } else {
            log.Println("[-] LDAP syncronization error, skipping...")
        }
    }

}
