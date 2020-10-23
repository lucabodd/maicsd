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
)

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


//slow tasks
/************************************
	Task executed every 10 minutes
*************************************/
func SshKeyExpire(mdb *mongo.Client, mongo_instance string, ldap *ldap_client.LDAPClient){
	log.Println("[*] Undergoing key expiration procedure")
	log.Println(" |___")

	// vars
	users := mdb.Database(mongo_instance).Collection("users")
	expirationDelta := 9

	findOptProj := options.Find().SetProjection(bson.M{"sys_username":1, "email":1, "pubKey": 1, "otp_secret":1, "key_last_unlock":1})
	cur, err := users.Find(context.TODO(), bson.M{ "pubKey": bson.M{ "$exists": true, "$nin": bson.A{nil, ""} }}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var user User
		err := cur.Decode(&user)
		Check(err)
		diff := TimeHoursDiff(user.Key_last_unlock)
		if (diff >= expirationDelta) {
			//cipher string only if it is unciphered
			if(strings.Contains(user.PubKey, "ssh-rsa")) {
				//return a byte string
				b32_decoded_otp_secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(user.Otp_secret)
				Check(err)
				key := b32_decoded_otp_secret
				encKey := AESencrypt(string(key), user.PubKey)
				_, err = users.UpdateOne(context.TODO(), bson.M{"email":user.Email }, bson.M{ "$set": bson.M{ "pubKey" : encKey}})
				Check(err)
				_, err = ldap.SetUserAttribute(user.Sys_username, "sshPublicKey", encKey)
				Check(err)
				log.Println("    |- SSH public key for user "+user.Sys_username+" Locked due to expiration")
			}
		}
	}
	log.Println("[+] Expired keys locked successfully")
}
